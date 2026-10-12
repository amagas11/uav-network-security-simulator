# A 接口：无线观测、密码与终端凭据

本文件冻结 B 侧接口边界。默认 V8 mock 模式继续用于历史回归；显式
`PERSON_A` 模式通过 `swarm_sim.integrations.person_a` 接入独立的人员 A 密码库。
A 源码不复制进 `swarm_sim`，B 也不重新实现 A 的 AES-GCM、SKG、Ed25519 或 HKDF。

## `LocalPhyObservation`

`ProbeService.probe(first_id, second_id, session_id=...)` 只允许直接双向邻居。
它返回相同 `probe_id`、业务 `session_id`、仿真时刻和频率下的两份端点本地观测：

```text
local_id, peer_id, session_id, probe_id, sim_time_s, freq_hz,
role(tx|rx), measurement_kind(rssi_dbm), measurement[],
snr_db, noise_var, missing, missing_reason
```

两份数组共享互易信道潜变量并分别叠加独立接收机噪声，不复制对端数组。
Person-A adapter 只通过 `obs.to_dict()` → A
`LocalPhyObservation.from_mapping(...)` 跨库转换，每个 `SkgEngine` 只收到本端观测。
非直接邻居、断链或双向频率不一致返回 `missing=true`，不补零、不伪造 CSI。
A 集成路径不调用 A 的 `synthesize_reciprocal_rssi` 或 `synthesize_eve_rssi`。

## 正式 Key control 与测试 raw-key contract

生产 `KeyProvider` 只提供非秘密控制面：

```python
reset(run_info)
key_reference(local_id, peer_id, session_id, key_epoch) -> KeyReference
request_rekey(local_id, peer_id, session_id, current_key_epoch) -> RekeyResult
```

生产协议中没有 `_key_material()`。历史 `TestOnlyAeadCryptoProvider` 所需的 raw key
被隔离在独立 `TestKeyMaterialProvider` 私有协议；`MockKeyProvider`/`NullKeyProvider`
仅为 TEST/兼容实现。Person-A coordinator 和 crypto adapter 均不实现或调用该接口。

人员 A 是 node-local provider：每个合法节点拥有独立 A `KeyProvider`、AEAD nonce
状态与 SKG engine；EXTERNAL 节点没有合法 provider。A 的 `encrypt()`/`decrypt()`
是业务密码边界，raw session key 永不返回 B。

## AES-GCM packet path

`PersonACryptoProvider` 的正式路径为（当前用于 Eavesdropping 保密链路及显式请求加密的业务）：

```text
business payload
→ A sender KeyProvider.encrypt
→ V8 Frame(ciphertext, nonce, algorithm, key handle, epoch)
→ V8 queue/PHY/loss/delay
→ A receiver KeyProvider.decrypt
→ AuthResult + business payload (only on PASS)
```

单一 `build_aad()` 同时供 protect/open 使用，绑定 message、逻辑声明、业务类型、
sequence、session、epoch、实际 hop endpoints、内部 immutable link 和 hop index。
密钥缺失时敏感包被 withheld 并产生 `KEY_UNAVAILABLE/SKG_REQUIRED`，不会发送明文、
不会 fallback mock key，也不会终止 runtime。密文/nonce/AAD 篡改返回认证失败且 payload
为 null。

事件只记录 `status/auth_result/key_id/key_epoch/algorithm/key_state/error_code`。
允许公开 nonce、算法和 key handle；禁止 raw key、私钥、credential master/serial、SKG
候选密钥及隐私放大中间量。

V10 的应用层 HMAC 是独立 B 侧业务认证层，不复用 Person-A session key、GCM tag、
Ed25519 或 SKG 中间材料。Spoofing/Flooding/FDI/Replay 单场景默认关闭 AES，但保留设备
独立 HMAC；其中 FDI 在 HMAC 生成后修改 payload，接收端由 HMAC mismatch 拒绝。该语义
不改变 Person-A upstream 算法或密钥边界。

## SKG 与 rekey

`PersonAKeyCoordinator` 使用业务 session 调用 V8 ProbeService。双方生成的
RECONCILE/CONFIRM 均被封装为签名的 `SKG_CONTROL`，实际进入 V8 TX queue、PHY 和 RX
handler；完整 public blob 仅在 runtime control payload 内处理，不成为 C 原始特征。
只有两端确认成功后，A `SkgEngine` 才在各自 A provider 内部 `put()` 密钥。

`REAUTH_REKEY_REQUEST` 在 Person-A 模式下表示已提交异步协商：先返回 `UPDATING`，
不提前递增节点 epoch；新的 Probe→RECONCILE→CONFIRM 完成后才切换 epoch。A provider
保留的上一 epoch 密文仍按 A 自身过渡语义解密。

## Identity、RFF 与 terminal credential

- A Ed25519 IdentityStore：认证首次 SKG control handshake；
- C RFF：物理发射机识别；
- A CredentialService：防复制 terminal credential。

三者不互相替代。当前联调身份由每 run 新生成并明确标记
`TEST_ONLY_GENERATED_IDENTITY`。`PersonATerminalAuthorizerAdapter` 将
`TerminalProfile.public_fingerprint()` 的 UTF-8 bytes 作为
`SIMULATED_TERMINAL_FINGERPRINT` 输入 A CredentialService；master key 与 serial 始终
保留在 adapter/A 内部，输出仅含 credential ID、状态和 failure code。

## 注入与成熟度

`PersonASecurityBundleFactory` 通过 `RuntimeDependencies.security_bundle_factory` 每 run
创建 fresh node providers、identities、credential service、coordinator 和 crypto adapter。
同一 `PlatformRuntimeFactory` 可供 Direct、SimulationManager/FastAPI、run_batch Python
API 和 UavDefenseEnv 使用。A 包缺失时，显式 Person-A 模式报
`PERSON_A_CRYPTO_NOT_AVAILABLE`；默认 mock 模式不受影响，绝不静默冒充 A 模式。

当前 provenance 为 `PERSON_A_INTEGRATED_DEVELOPMENT`：密码算法是真实 AES-256-GCM、
Ed25519 与 HKDF，但观测仍来自仿真、联调身份/credential 不是正式资产，因此不得宣称
FORMAL，也不解除最终正式实验的外部依赖。
