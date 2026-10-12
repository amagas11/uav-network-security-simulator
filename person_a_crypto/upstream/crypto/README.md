# crypto（给 B 的调用说明）

邻接链路密码库。包根是 `无人机/`（`from crypto...`）。Python 3.11。契约见 `docs/人员A/A1-观测与密码接口.md`。

**这是可 import 的库，不是已经挂上仿真。** 不要拷进 `无人机网络攻防仿真平台_V1/`。不要把本库的 `KeyProvider` 直接塞进 `PlatformRuntime(key_provider=...)`：V1 mock 会抽 `_key_material`，正式路径只调 `encrypt` / `decrypt`，密钥字节不出 A 模块。日志和前端只记 `key_id` / `status`，不要打印密钥、nonce 种子、协商中间量。

当前未做：协商报文走无线、节点主路径接入、A7 接入 V1 `TerminalAuthorizer`。V1 已有成对 RSSI 探测；有探测 ≠ 已接 SKG。合成 RSSI / 合成 Eve 只用于离线单测，不要当平台信道输出。

测试向量：`crypto/test_vectors.json`（`TEST_ONLY`，不是生产密钥）。对照单测：`tests/test_vectors.py`。

```text
cd e:\project_cursor\uav_task\无人机
py -3.11 -m pip install -r requirements-crypto.txt
py -3.11 -m pytest tests/test_credentials.py tests/test_vectors.py tests/test_aead.py tests/test_key_provider.py tests/test_identity.py tests/test_skg.py tests/test_skg_eve.py -q
```

---

## 1. 失败码（稳定字符串）

| 码 | 何时 |
|----|------|
| `ok` | 成功 |
| `key_unavailable` | 无密钥、已撤销、SKG 未确认 |
| `key_expired` | 超时，需重协商 |
| `auth_fail` | 篡改、错密钥、错方向 |
| `nonce_reuse` | 该发送方向 nonce 用尽或重复 |
| `identity_fail` | 预置身份校验失败 |
| `skg_fail` | 量化 / 协调 / 确认失败 |
| `credential_fail` | 终端指纹与序列号不匹配 |
| `bad_argument` | 参数不合法 |

失败时：无明文、无密文、不退回测试密钥。检测器只看 `CryptoResult.auth`（`AuthResult`），不要再对密文做无密钥 SHA-256。

---

## 2. 业务加解密（有钥匙之后）

每节点一个 `KeyProvider`。业务**不要**传 `key=`。密钥只通过 `put`（或将来 SKG 确认后内部 `put`）进入模块。

```python
from crypto.key_provider import KeyProvider

# 仅演示：正式路径应由 SKG 写入，不要在日志里打 key
key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
aad = b"src=3,dst=7,seq=18,msg_type=data,key_epoch=0,direction=3->7"

node3, node7 = KeyProvider(3), KeyProvider(7)
node3.put(7, "link-3-7-s1", key, key_epoch=0)
node7.put(3, "link-3-7-s1", key, key_epoch=0)

enc = node3.encrypt(3, 7, "link-3-7-s1", b"mission-cmd-42", aad)
# enc.status == "ok"；enc.ciphertext / enc.nonce 随包发送；enc.key_id 可上日志

dec = node7.decrypt(
    7, 3, "link-3-7-s1", enc.ciphertext, aad,
    nonce=enc.nonce, key_id=enc.key_id, key_epoch=enc.key_epoch,
)
# dec.status == "ok" 且 dec.plaintext == b"mission-cmd-42"
```

对照向量 `aead`：同一把测试钥、同一 AAD、每个 `AeadService` **第一次**加密的 nonce / 密文必须与 JSON 一致。改密文或用发送端当接收端解 → `auth_fail`。

算法：AES-256-GCM。`3->7` 与 `7->3` 分 nonce 空间。`aad` 建议含 `src, dst, seq, msg_type, key_epoch, direction`（保持明文便于路由）；业务体进 `plaintext`。

组包（加密成功后设 `is_encrypted: true`）：

```json
{
  "ver": 1,
  "seq": 18,
  "src": 3,
  "dst": 7,
  "is_encrypted": true,
  "key_id": "k-3-7-link-3-7-s1-e00",
  "key_epoch": 0,
  "alg": "AES-256-GCM",
  "nonce": "<base64>",
  "data": { "ciphertext": "<base64>" },
  "signature": null
}
```

`signature` 作废。解密失败保持密文，`auth.status = auth_fail`。

`get_status`：`ok` / `key_unavailable` / `key_expired` / `key_revoked`。撤销后加密 → `key_unavailable`；过期后加密 → `key_expired`。换 epoch 后新加密用新钥匙，上一把在过渡期内仍可解密。

底层 `crypto.aead.AeadService` 仍接受 `key=`，只给 KeyProvider 内部用。

**注入时机（现有 step 顺序要改）：** 合法节点失陷的 FDI 在**加密前**改业务；外部改密文在**加密后、信道前**；窃听只复制密文，Eve 无密钥不得明文。

---

## 3. 观测（SKG 输入）

业务包上的标量 `rssi_dbm` / `snr_db` **不能**喂给 SKG。用探测得到的 `LocalPhyObservation`（V1：`ProbeService.probe` 再 `to_dict()` / `from_mapping`）。

每端只看见自己的量测。平台可以一次 `probe()` 得到两端，但每个 `SkgEngine` 只吃本端那份。配对靠同一 `probe_id`。没有 `get_peer_observation()`。

`measurement` 是 RSSI 序列（dBm），**长度未锁死**：V1 默认 16，离线合成默认 64，两端同一次探测须等长。本阶段只有 `"rssi_dbm"`，不要伪造 CSI。

`missing=true` 时 `measurement` / `snr_db` / `noise_var` 为 `null`，不要补零。A 返回 `skg_fail`。

---

## 4. SKG 调用顺序（A 生成 blob，B 当普通包传）

每节点：`KeyProvider` + `SkgEngine(local_id, key_provider)`。协商内容公开，不能当 AES 密钥。

建议报文：`msg_type: "skg"`，字段 `src, dst, probe_id, skg_phase, blob`。必须走与业务相同的丢包/延迟；断链则 SKG 失败，不设旁路。V1 **尚未**传这种报文。

```python
from crypto.key_provider import KeyProvider
from crypto.observations import LocalPhyObservation
from crypto.skg import SkgEngine

kp3, kp7 = KeyProvider(3), KeyProvider(7)
skg3, skg7 = SkgEngine(3, kp3), SkgEngine(7, kp7)

# obs_* 来自 ProbeService，不要用 synthesize_* 冒充仿真
skg3.on_local_observation(obs3)  # 只含节点 3 的 measurement
skg7.on_local_observation(obs7)

rec3 = skg3.make_reconcile_blob(probe_id)  # skg_phase=reconcile
rec7 = skg7.make_reconcile_blob(probe_id)
skg3.apply_reconcile_blob(probe_id, rec7)  # 也可只传 rec7.blob
skg7.apply_reconcile_blob(probe_id, rec3)

conf3 = skg3.make_confirm_blob(probe_id)  # skg_phase=confirm
conf7 = skg7.make_confirm_blob(probe_id)
done3 = skg3.apply_confirm_blob(probe_id, conf7)
done7 = skg7.apply_confirm_blob(probe_id, conf3)
# 两边 status=="ok" 后钥匙已 put；此后走第 2 节 encrypt/decrypt
```

当前协调是**综合征一致则通过**，不是纠错码。比特对不上、观测 missing、确认失败 → `skg_fail`，不 `put`。

对照向量 `skg`（合成 seed=42，**不是**仿真观测）：公开 blob 与确认成功后**第一次** `encrypt` 的 nonce/密文须一致。向量里**没有**会话密钥。`skg_fail_scrambled`：对端量测打乱 → `skg_fail`，随后加密 `key_unavailable`。

离线造数（不要接到仿真主循环）：`synthesize_reciprocal_rssi`、`synthesize_eve_rssi`。Eve 须独立/弱相关信道，禁止复制 Alice 数组加噪。

---

## 5. 预置身份（第一次协商，与会话密钥无关）

SKG 开始前没有信道密钥，用 Ed25519 证明「我是节点 3」。与 V1 `TerminalProfile`、C 的 RFF 都不是一回事。身份签名**尚未**包进 `skg.py`；B 可在收发 blob 前后自行调用。

启动时每节点 `IdentityStore.load`，并把邻居公钥 `trust_public`。私钥只留在 A 模块。

```python
from crypto.identity import IdentityStore

n3 = IdentityStore.load({
    "node_id": 3,
    "identity_id": "uav-3",
    "public_key_pem": "...",
    "private_key_pem": "...",
})
n7 = IdentityStore.load({...})  # 节点 7
n7.trust_public(n3.public_material())

signed = n3.sign_handshake(3, 7, "link-3-7-s1", "prb-00042", rec3.blob)
n7.verify_handshake(
    7, 3, "link-3-7-s1", "prb-00042", rec3.blob,
    signature=signed.signature,
    identity_id=signed.identity_id,
    public_key_pem=signed.public_key_pem,
)
# 失败 → identity_fail
```

对照向量 `identity`：其中 PEM 为 `TEST_ONLY`，仅用于对齐签名，不要当外场密钥、不要打到日志。

---

## 6. 给 C（经 B）

只给 `AuthResult`：`status`、`key_id`、`key_epoch`、`alg`、`local_id`、`claimed_src`。不要给密钥、nonce 种子、SKG blob 的派生中间值。

---

## 7. 终端凭据（A7，未接入 V1）

B 在登记时调用 `derive`，在启动 / 入网 / 敏感命令时调用 `verify`。输入是不透明的 `bytes` 指纹（采集由 B 做），不是 A4 Ed25519、不是 C 的 RFF、也不解析 V1 `TerminalProfile`。本接口**没有**接到 `TerminalAuthorizer`。内部主密钥只在构造时注入，返回值和日志只有 `credential_id` 句柄；成功 `derive` 另给 `serial`。不要打印主密钥或原始指纹。

```python
from crypto.credentials import CredentialService

# 仅演示：32 字节内部主密钥，不要打到日志
master_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
svc = CredentialService(master_key)

enrolled = svc.derive(fingerprint, terminal_id="gcs-1")
# enrolled.status == "ok"；保存 enrolled.serial；日志用 enrolled.credential_id

checked = svc.verify(fingerprint, enrolled.serial, terminal_id="gcs-1")
# checked.status == "ok"；指纹对不上 → credential_fail，且不返回 serial
```

空指纹 → `bad_argument`。算法：HKDF-SHA256。
