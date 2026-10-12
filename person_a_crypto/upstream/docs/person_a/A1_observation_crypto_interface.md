# A1 观测与密码接口（草案 v0.1）

发给 **B** 确认，**C** 只需看第 5 节 `AuthResult`。本文是冻结契约，不是实现。A 按此写 A2–A6；B 按此改信道与调用点。有分歧就改这一页，不要各自改代码。

**版本：** 0.1（草案）。观测字段已与 B 的 V1 `ProbeService` 对齐。  
**A 维护字段语义，B 维护仿真里如何产生这些字段。**  
修订：`snr_db` 在顶层；无 `quality`；可用性只看 `missing`。2026-09-07 与 V1 平台 `docs/a_integration_interface.md` 对齐，见第 2.0、3.0、4、6、7 节。

---

## 0. 怎么对接（给 A 用）

1. 观测字段单独发给 B：[A1-B所需无线观测.md](A1-B所需无线观测.md)（本文第 2 节的摘录）。说明现有 `rssi_dbm`/`snr_db` **不能**当 SKG 输入。加解密仍用本文，请 B 填第 8 节。
2. 抄送 C 第 5 节，问检测器是否还要别的非秘密字段（**不要密钥**）。
3. B 回复三种结果即可：同意 / 改某字段 / 本阶段做不到（标假设）。
4. 确认前 A 仍按草案实现；字段改了再微调，不必停工。
5. 本文 1.0 之前，B 不要把 Base64 接口写死成最终加密格式。

当前：旧 `无人机/` 里业务信道仍是单向标量 SNR。B 的 V1 平台已用 `ProbeService.probe` 提供成对探测观测（RSSI 序列）。SKG 算法仍未接入 V1；有探测不等于已完成密钥生成。

---

## 1. 职责切分

| 事项 | A | B |
|------|---|---|
| 观测字段含义、单位、缺失标记 | 定义 | 在 PHY/节点上产生并只送给本端 |
| 协商/密钥消息怎么走无线 | 给出明文/密文类型和方向 | 当普通报文传，断链就失败，不设旁路 |
| `encrypt` / `decrypt` / `KeyProvider` | 实现 | 在正确阶段调用 |
| 预置身份加载到节点 | 定义材料格式 | 初始化时写入各节点 |
| 日志与前端 | 只输出句柄和状态 | 不得打印密钥、nonce 种子、原始指纹 |

密钥按**直接邻接链路**维护。Leader 转发时，GCS 不得用转发信号当原发送端的 SKG 观测。

---

## 2. 信道观测（SKG 用，B 提供）

发给 B 的独立说明：[A1-B所需无线观测.md](A1-B所需无线观测.md)。下面与该摘录保持一致；改字段先改本节，再同步摘录。

业务信道的 `last_channel_meta` 可继续给前端。SKG **另走探测观测**，不要和业务 SNR 混用。

### 2.0 与 V1 平台对齐（2026-09-07 总控拍板）

对照 B 的 `docs/a_integration_interface.md` 与 `swarm_sim/probe.py`：

1. **V1 / 本阶段只做 RSSI**（`measurement_kind: "rssi_dbm"`）。不伪造 CSI。表中 `"csi"` 是以后取值，当前量化只走 RSSI。
2. **`missing=true` 时 `measurement`、`snr_db`、`noise_var` 用 `null`**，不补零、不要求空数组。A 视为不可用量测，返回 `skg_fail`。接入时用 dict / `from_mapping`，不要把 B 的 dataclass 直接当 A 的类型。
3. **允许平台一次 `probe()` 得到两端观测**，再分别交给各端 SKG。禁止把对端数组塞进同一个 `on_local_observation`。
4. **`sim_time_s` 两端相同或略差均可**（V1 现为同一仿真时刻，可接受）。
5. 下列密钥/凭据/协商边界见第 3.0、4、6、7 节：正式密钥不出 A 模块；V1 mock AEAD 只联调；TerminalProfile ≠ 预置身份；协商报文本阶段未进 V1，不能声称已接 SKG。

### 2.1 `LocalPhyObservation`（每一端只看见自己的）

| 字段 | 类型 | 说明 |
|------|------|------|
| `local_id` | int | 本节点 |
| `peer_id` | int | 对端（直接邻居） |
| `session_id` | str | 链路会话，例如 `link-3-7-s1` |
| `probe_id` | str | **两端必须相同**，用于配对 |
| `sim_time_s` | float | 仿真时刻，不用墙上时钟。两端相同或略差均可 |
| `freq_hz` | float | 探测载频，当前基线 3.5e9 |
| `role` | `"tx"` / `"rx"` | 本端在这次探测里是发还是收 |
| `measurement_kind` | `"rssi_dbm"` 或 `"csi"` | **V1 / 本阶段只用 `"rssi_dbm"`**；`"csi"` 延后，V1 不伪造 |
| `measurement` | list[float] 或 `null` | 本端量测（RSSI，dBm）；**禁止**带对端原始值。`missing=true` 时为 `null` |
| `snr_db` | float / null | 本端对该次**探测**的信噪比估计；`missing=true` 或没有则为 `null`。不是业务包标量 SNR |
| `noise_var` | float / null | 本端噪声方差；`missing=true` 或没有则为 `null` |
| `missing` | bool | 本次本端观测**不能**给 SKG 用。`true` 时 A 返回 `skg_fail`，量测字段为 `null`，不要补默认数 |

`missing=false` 且 `measurement` 为非空数组，A 才量化。无单独的 `quality` / `valid`。

**Eve** 若参与实验：同一 `probe_id` 另给一份 `LocalPhyObservation`，`local_id` 为窃听者。A 用它做离线评估；节点检测器不得读取 Eve 观测。

### 2.2 B 必须保证的物理语义

1. 一次探测：邻接两端各产生一条观测，`probe_id` 相同；`sim_time_s` 相同或接近。
2. 互易针对**信道**，两端接收噪声独立，不能复制一端数组再加噪冒充另一端。
3. 探测失败则该端 `missing=true`，量测为 `null`，A 返回密钥生成失败。
4. 中继只对自己的邻接链路有观测，没有“源到宿一条 CSI”。
5. 仿真器可以一次函数调用生成两端观测，但每个 SKG 引擎只吃本端那一份。

### 2.3 样例（节点 3 收到针对节点 7 的探测）

```json
{
  "local_id": 3,
  "peer_id": 7,
  "session_id": "link-3-7-s1",
  "probe_id": "prb-00042",
  "sim_time_s": 12.040,
  "freq_hz": 3500000000,
  "role": "rx",
  "measurement_kind": "rssi_dbm",
  "measurement": [-71.2, -70.8, -71.5, -70.9],
  "snr_db": 14.1,
  "noise_var": null,
  "missing": false
}
```

本阶段 / V1 只提供互易 RSSI 序列。CSI 延后。

`missing=true` 时样例：`"measurement": null, "snr_db": null, "noise_var": null, "missing": true`。

### 2.4 观测怎么交给 A（采集属 B，算法只消费本端）

V1 允许：

```text
obs_a, obs_b = ProbeService.probe(first_id, second_id)   # 平台一次得到两端
skg_a.on_local_observation(obs_a)   # 只含 first 的量测
skg_b.on_local_observation(obs_b)   # 只含 second 的量测
```

A **不**提供 `get_peer_observation()`。配对靠同一 `probe_id`。名字可改，约束不变。

### 2.5 和现有代码字段什么关系

仓库里**已经有一批字段**，但是给业务仿真、前端和规则检测用的，**不是**预先定义好的 SKG/密钥契约。A1 是按 [分工安排.md](../分工安排.md) 第 7.1 节的最小约定**新起草**的。

现有 `payload_obj`（`traffic_model` / `packet_generate`）：

`ver, seq, src, dst, timestamp, is_encrypted, traffic_type, traffic_profile, payload_size_bytes, simulation_time_s, arrival_interval_s, data, signature`

现有 `last_channel_meta`（`NRChannel.transmit`）：

`distance_m, snr_db, sinr_db, rssi_dbm, path_loss_db, fspl_db, shadowing_db, rician_fading_gain_db, noise_power_dbm, interference_power_dbm, per, link_id, …`

现有假加密嵌在 `data` 里：`cipher, algorithm, key_id, salt`。

| A1 字段 | 现有代码 | 关系 |
|---------|----------|------|
| `src` / `dst` / `seq` / `is_encrypted` | 已有 | **沿用**，进 AEAD 的 AAD |
| `simulation_time_s` | 业务包已有 | SKG 观测用同名仿真钟，**不要**用 `timestamp`（墙上时钟） |
| `rssi_dbm` / `snr_db` | 业务信道已有，标量、单向 | **不能直接当** `LocalPhyObservation.measurement`；名字可复用，语义要成对探测序列 |
| `key_id` | 现写在 `data.key_id` | A1 改到包根上，且必须是句柄不是 `"UAV-3-KEY-001"` 这种假 ID |
| `signature` | 无密钥 SHA-256 | **废弃**，改 `AuthResult` |
| `probe_id, session_id, key_epoch, measurement[], AuthResult, msg_type=skg` | 旧平台没有 | V1 已有探测观测；**协商报文 `msg_type=skg` 尚未接入** |

分工安排里 B→A 的最小集是：本地节点、对端会话、`probe_id`、频率、仿真时刻、量测数组、质量。A1 第 2.1 节覆盖了这一集，并补了 `role / measurement_kind / missing / noise_var`，否则量化无法实现。

### 2.6 后续字段不完备：有风险，但可控

**会缺的**（本版故意不写死，避免一次设计成完整 PHY）：

- CSI 维度：子载波数、导频长度、采样率、天线索引、探测带宽
- 探测功率、AGC、校准版本（`CalibrationProfile` 属 B）
- 配对时间窗的具体秒数、时钟偏差模型
- 群组密钥、广播、多跳共享密钥（A1 只做邻接单播）
- C 的重密钥策略字段、防复制指纹字段（A7 另约）
- 合同上的 `contract_version`（升 1.0 时应加上）

**相对安全、不太会推翻的：** 失败码、`key_id`/`key_epoch`、GCM 包形态、每端只见自己的量测、`probe_id` 配对。这些是接入加密的最小闭环。

**扩展规则（B/A 共同遵守）：**

1. 只**新增可选字段**，不改已有必填字段的含义和单位。
2. 接收方不认识的键忽略；可选字段为 `null` 或缺失时由 A 自行判断，SKG 显式失败或降级，禁止猜默认密钥。
3. `measurement_kind` 增加新取值（如 `"csi_v2"`）时，旧的 `"rssi_dbm"` 路径必须仍能跑。
4. 改必填语义必须升契约版本（0.1 → 1.0 → 1.1），并改测试向量。

因此：A1 对 **A2 加密接入** 是够用的；对 **论文级 SKG / 实测 CSI** 几乎肯定要加可选字段。V1 / 本阶段只做 RSSI、CSI 延后、Eve 用合成，已写入第 2.0 节。

---

## 3. 密码服务与 KeyProvider（A 实现，B 调用）

建议模块路径（实现阶段）：`crypto/`。B 的 V1 通过 `PlatformRuntime(..., key_provider=..., crypto_provider=...)` 注入；旧入口是 `UAVNode.encrypt_packet`。

### 3.0 与 V1 mock 密钥的分期

- **V1 现在的 `MockKeyProvider` / `_key_material` / `TestOnlyAeadCryptoProvider` 只用于平台联调**，状态是 `TEST_ONLY_NOT_SKG`，不能当 SKG 实验结论。
- **正式接入以 A 为准：** `KeyProvider.put` 之后只调 `encrypt` / `decrypt`；原始密钥字节不出 A 模块；日志只有 `key_id` / 句柄和状态。不要把 `_key_material` 当成生产接口。
- 接上 SKG 之前，V1 可继续用 mock 跑攻击与检测。

### 3.1 标识与句柄

| 名称 | 含义 |
|------|------|
| `key_id` | 句柄，可上日志，例如 `k-3-7-s1-e04` |
| `key_epoch` | 单调版本 |
| `direction` | `"3->7"` 与 `"7->3"` 分密钥或分 nonce 空间，不得混用 |
| 原始密钥字节 | 只留在 A 模块内 |

密钥查找键：`(local_id, peer_id, session_id, key_epoch)`。缺省用当前可用 epoch。

### 3.2 失败码（稳定字符串，B/C 按码分支）

| 码 | 何时 |
|----|------|
| `ok` | 成功 |
| `key_unavailable` | 无密钥、已撤销、未完成确认 |
| `key_expired` | 超时需重协商 |
| `auth_fail` | 密文认证失败（篡改、错密钥、错方向） |
| `nonce_reuse` | 发送方向 nonce 用尽或重复（A 内部应尽量避免；一旦发生必须失败） |
| `identity_fail` | 预置身份校验失败（首次协商） |
| `skg_fail` | 量化/协调/确认失败 |
| `bad_argument` | 调用参数不合法 |

失败时：**不**返回明文，**不**退回测试密钥。

### 3.3 调用签名（约定）

```text
encrypt(local_id, peer_id, session_id, plaintext: bytes, aad: bytes) -> CryptoResult
decrypt(local_id, peer_id, session_id, ciphertext: bytes, aad: bytes) -> CryptoResult

CryptoResult:
  status: 上述失败码之一
  key_id: str | null
  key_epoch: int | null
  ciphertext: bytes | null     # encrypt 且 ok
  plaintext: bytes | null      # decrypt 且 ok
  nonce: bytes | null          # 可随包公开发送；不是密钥
  auth: AuthResult             # 见第 5 节
```

`aad`（附加认证数据）建议包含：`src, dst, seq, msg_type, key_epoch, direction`。B 组包时这些字段保持明文，便于路由；`data` 业务体进 `plaintext`。

**算法（A 拟定，B 无需自实现）：** AES-256-GCM。包上可带 `alg: "AES-256-GCM"`、`key_id`、`nonce`（Base64）、`ciphertext`（Base64）。不要再把盐和明文拼进 Base64 冒充 GCM。

### 3.4 报文里加密后的 `payload_obj` 形态

加密成功后，B 应把业务 `data` 换成密文包装，并设 `is_encrypted: true`：

```json
{
  "ver": 1,
  "seq": 18,
  "src": 3,
  "dst": 7,
  "timestamp": 12.04,
  "is_encrypted": true,
  "key_id": "k-3-7-s1-e04",
  "key_epoch": 4,
  "alg": "AES-256-GCM",
  "nonce": "<base64>",
  "data": { "ciphertext": "<base64>" },
  "signature": null
}
```

`signature` 字段作废：完整性由 GCM 认证标签承担。检测器看 `AuthResult`，不要再对密文做无密钥 SHA-256。

解密成功后，A 只还原 `plaintext` 对应的业务 `data`；B 负责写回 `payload_obj`。解密失败保持密文，`auth.status = auth_fail`。

### 3.5 B 必须调整的调用时机（现有 bug）

当前 `step` 是：**先 `encrypt_packet`，再注入攻击**。FDI 改的是包装字段，随后解密可能把攻击改掉。约定：

| 注入类型 | B 的阶段 | A |
|----------|----------|---|
| 合法节点失陷后的 FDI | **加密前**改业务 `data` | 照常加密；认证可能通过 |
| 外部改密文 | **加密后、信道前**改 `ciphertext`/`nonce` | `decrypt` → `auth_fail` |
| 窃听 | 信道上复制密文；Eve 无密钥则不能得明文 | 不提供“检测窃听成功” |

A 保证：加解密只处理 bytes，不解析业务命令，避免和攻击对象缠在一起。

### 3.6 `KeyProvider` 事件（可上日志）

```json
{
  "event": "key_ready | key_failed | key_expired | key_revoked | rekey_ok",
  "local_id": 3,
  "peer_id": 7,
  "session_id": "link-3-7-s1",
  "key_id": "k-3-7-s1-e04",
  "key_epoch": 4,
  "status": "ok",
  "sim_time_s": 12.1
}
```

---

## 4. SKG 协商消息（A 生成内容，B 当报文传）

协商内容对无线是**公开**的（校验码、纠错综合征等），不能当密钥。

B 增加报文类型即可，例如 `msg_type: "skg"`，`data` 为不透明对象：

```json
{
  "msg_type": "skg",
  "src": 3,
  "dst": 7,
  "probe_id": "prb-00042",
  "skg_phase": "reconcile | confirm",
  "blob": "<base64 或 json，A 定义>"
}
```

- 必须走与业务相同的逐跳/丢包模型，失败则 SKG 失败。
- 首次协商用**预置身份**做源认证（第 6 节），不能用还没生成的 SKG 密钥保护第一次协商。
- 确认成功后 A 才 `key_ready`，此后业务才允许 `encrypt`。

**V1 / 本阶段：** 平台尚未传输上述协商报文。探测观测对齐 **不等于** 已接入密钥生成。协商进 V1 接入说明之后，才能声称 SKG 接到仿真。

---

## 5. `AuthResult`（给 C，经 B 接入检测）

C 只能用这些字段，不能要密钥、nonce 种子、协商 `blob` 的密钥推导中间量。

```json
{
  "status": "ok | auth_fail | key_unavailable | unencrypted | identity_fail",
  "key_id": "k-3-7-s1-e04",
  "key_epoch": 4,
  "alg": "AES-256-GCM",
  "local_id": 7,
  "claimed_src": 3
}
```

| `status` | 含义 |
|----------|------|
| `ok` | 认证解密成功，**不**表示业务内容真实 |
| `auth_fail` | 密文不可信，规则层应硬失败，模型低分不能覆盖 |
| `key_unavailable` | 无会话密钥 |
| `unencrypted` | 明文到达（防御未开或对端未加密） |
| `identity_fail` | 预置身份未通过 |

---

## 6. 预置身份（首次协商根）

SKG 密钥不能认证第一次 SKG。B 在 `init` 时为每个节点加载 A 指定格式的材料，例如：

```json
{
  "node_id": 3,
  "identity_id": "uav-3",
  "public_key_pem": "...",
  "private_key_pem": "..."
}
```

（若改用预共享 HMAC 密钥，则改为 `psk_id` + 仅本节点持有的密钥句柄，仍由 A 定义字节格式。）

- 私钥只进 A 模块，不上日志。
- 材料由 B 从配置注入；A 提供 `sign_handshake` / `verify_handshake`。
- 节点身份与射频指纹（C 的 RFF）不是一回事。
- **与 V1 `TerminalProfile` 不是一回事。** 预置身份认证「第一次 SKG 握手是不是这架飞机」；TerminalProfile 是启动/入网/敏感命令的防复制绑定（A7）。本阶段 A 不做终端凭据。

---

## 7. 明确不做（本契约范围外）

- 防复制状态机、终端指纹采集、V1 `TerminalAuthorizer`（A7 另接口，B 后接；本阶段 A 不做）
- 策略何时重密钥（C 出策略，B 转发，A 执行）
- 把现有单次业务 `rssi_dbm` 直接喂给 SKG
- 把 V1 mock 密钥或 `_key_material` 写成已完成 SKG
- 在协商报文进入 V1 之前声称平台已接入密钥生成

---

## 8. 请 B 确认（直接在副本上填）

| # | 问题 | B 填写（是 / 否 / 改成…） |
|---|------|---------------------------|
| 1 | 本阶段探测量测用 `rssi_dbm` 序列，CSI 是否延后？ | **已对齐：V1 / 本阶段只做 RSSI，不伪造 CSI** |
| 2 | 一次探测两端 `probe_id` 相同；`sim_time_s` 相同或略差？ | **已对齐：相同或略差均可；V1 现为同一时刻** |
| 3 | 协商报文能否按业务报文走信道（可丢、可延迟）？ | **本阶段不做；V1 尚未传 SKG blob。有探测 ≠ 已接 SKG** |
| 4 | 加密前 FDI 与加密后篡改能否分成两个注入点？ | |
| 5 | `init` 能否加载第 6 节预置身份？ | 与 TerminalProfile 分开；本阶段 A 不做终端凭据 |
| 6 | 日志/前端是否同意只记 `key_id`/`status`？ | **正式接入：密钥不出 A 模块。V1 `_key_material` 仅 mock 联调** |
| 7 | Eve 观测是否本阶段就要，还是 A 先用合成 Eve？ | A 先用合成 Eve（A6） |
| 8 | Python 版本与依赖（建议 3.11 + `cryptography`）是否对齐？ | |
| 9 | 模块目录 `crypto/`、由 B 在节点内调用，是否同意？ | V1 注入点为 `key_provider` / `crypto_provider`；正式实现用 A 的 `encrypt`/`decrypt` |

请 C 确认：第 5 节字段是否够用；缺什么（仍禁止密钥类字段）。

---

## 9. 测试向量约定（A 随后在 A8 提供）

B 接入时至少跑通：

1. 有密钥：加密 → 解密，业务 `data` 一致，`AuthResult.status=ok`
2. 改密文字节：`auth_fail`，无明文
3. 无密钥：`key_unavailable`
4. 合成双端观测（相关 + 独立噪声）：可确认则 `key_ready`；打乱一端则 `skg_fail`
5. 密钥不出现在返回给前端的 JSON 中

A 在实现 A2 后补一组固定种子的 hex 样例附在本目录或 `crypto/README`。
