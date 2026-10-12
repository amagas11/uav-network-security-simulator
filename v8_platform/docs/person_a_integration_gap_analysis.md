# Person-A Crypto 与 V8 集成差距分析

## 输入与边界

- B 基线：`无人机网络攻防仿真平台_V8.zip`，SHA-256
  `218dc1aafe2c9187cc210cabcd4ebf4d22e87b24a83a1eed3e0d922291326b21`。
- A 上游：`人员A-crypto-交付.zip`，SHA-256
  `fd37cfd8370d7f899c2fc4913227f24113080044e3a55cd40c1a321178818aa9`。
- A 的 upstream 保持唯一独立 copy。最终 polish 只对 `crypto/key_provider.py` 增加最小
  `rollback_epoch()` 生命周期 API；`aead.py`、`skg.py`、`identity.py`、
  `credentials.py` 的 SHA-256 均与输入 ZIP 一致。

## 接口冲突与处理

| 项目 | A semantic | V8 baseline semantic | 责任/风险 | 解决结果 |
|---|---|---|---|---|
| Provider ownership | 每个合法节点一个 `KeyProvider(local_id)` 与独立 nonce state | runtime-level key/crypto provider | B adapter；全 swarm 共用 A node0 会破坏方向与隔离 | `PersonAKeyCoordinator` 管理 node-local providers，EXTERNAL 无 provider；RESOLVED |
| Raw-key boundary | 正式业务只调用 A `encrypt/decrypt`，raw key 不离开 A | 历史 test AEAD 依赖 `_key_material` | B contract gap | 正式 `KeyProvider` 去掉 raw API；另立 `TestKeyMaterialProvider` 仅供 test adapter；RESOLVED |
| Crypto result | A 返回小写稳定码与 `AuthResult` | V8 需要 PASS/FAIL、key state 与 payload | B mapping | `PersonACryptoProvider` fail-closed 映射；失败无明文；RESOLVED |
| Probe typing | A 接受自己的 dataclass/mapping，每端只见本端 | V8 返回 B dataclass pair | B adapter | 强制 `to_dict()`→`from_mapping()`，分别调用两 engine；RESOLVED |
| Probe session | SKG key 由 `(local, peer, session, epoch)` 查找 | V8 probe 默认新建 session | B compatibility gap | `ProbeService.probe(..., session_id=...)` 可绑定业务 session，默认行为不变；RESOLVED |
| Reciprocal quantization | A v0.1 仅校验量化 syndrome 完全一致，无纠错 | V8 原始单高斯 reciprocal fading + 独立端噪声可产生 bit mismatch | A 算法限制；不得污染 B 默认信道 | `V8_DEFAULT` 已逐值恢复；另设显式 `PERSON_A_V01_COMPAT_TEST` 双状态 profile，仅验证 adapter，TEST_ONLY；FORMAL GAP 记录为 A-CHANGE-001 |
| SKG transport | A 只生成/apply public blobs，B 必须当网络报文传 | V8 baseline 尚无 SKG control handler | B integration | 签名 `SKG_CONTROL` 进入 queue→TX→PHY→RX；断链/丢失触发 timeout，无旁路；RESOLVED |
| Confirm commit | A `apply_confirm_blob()` 内部立即 `KeyProvider.put()` | 单侧 confirm 丢失会造成 half-key 风险 | B integration transaction boundary | 两端 authenticated confirm 先 pending/cross-verify，随后 pair commit；冲突/丢失时两端均无新 epoch；RESOLVED |
| Commit exception rollback | A `revoke()` 不恢复 previous outbound current；A encrypt 又不允许 B 指定 epoch | 第一端 commit 后第二端异常会令 B reference 与 A effective current 不一致 | A lifecycle contract gap；B 禁止 private/raw-key hack | A 最小公开 `rollback_epoch()` + B recorded transaction context；A32–A35 PASS；`REQUIRES_PERSON_A_ACCEPTANCE` |
| Concurrent rekey | A engine 是单次局部会话对象 | 重复/反向请求可能为同一 epoch 创建多个 probe/engine | B orchestration | `RekeyCoordinator` 以 pair/session/target epoch 唯一化，重复返回 `existing_rekey_in_progress`；RESOLVED |
| First-handshake identity | Ed25519 对 src/dst/session/probe/blob 签名 | TerminalProfile/RFF 是不同身份域 | B integration | 独立 IdentityStore 信任库；verify 后才 apply/commit；RESOLVED |
| Rekey | 新 epoch 必须重新 Probe/SKG/confirm | baseline mock 可同步 epoch++ | B lifecycle gap | action 只表示 request accepted/UPDATING；网络 SKG 完成后才切 epoch；RESOLVED |
| Terminal credential | A `CredentialService` 接收 opaque fingerprint bytes | V8 `TerminalProfile`/`TerminalAuthorizer` | B adapter | public fingerprint 转为明确的 simulated fingerprint；master/serial 内部保存；RESOLVED |
| Provenance/maturity | A 输出非秘密状态/句柄 | V8 run record 需要 provider status | B integration | name/version/mode/status 写 runs；标 `PERSON_A_INTEGRATED_DEVELOPMENT`，不冒充 FORMAL；RESOLVED |
| Package unavailable | A 是可选独立库 | V8 默认 tests 不应依赖 A | B integration | 仅显式 A mode 报 `PERSON_A_CRYPTO_NOT_AVAILABLE`，default mock 正常；RESOLVED |

## 责任判断

本轮 B-side half-commit、exception rollback 与 rekey concurrency 已关闭。由于 A 原公开
API 无法恢复 actual outbound current，本补丁对 A `key_provider.py` 作了最小生命周期扩展；
没有修改任何密码算法，也没有向 B 暴露 key material。
A v0.1 SKG 的“无纠错、必须量化完全一致”仍是正式信道兼容性缺口：原始 V8 默认 profile
下的确定性反例会返回 `SKG_RECONCILE_MISMATCH`，而显式 compatibility profile 可完成
联调。后者不能替代真实测量成功率，因此已形成 A-CHANGE-001；它不阻塞
INTEGRATED_DEVELOPMENT baseline，但阻塞 FORMAL SKG 结论。

## 保留外部依赖

- 正式 Ed25519 私钥生命周期、信任根和安全存储；
- 正式 terminal credential master/secure element；
- 最终批准并校准的 reciprocal RF measurement/IQ；
- 人员 A 对真实测量下 SKG 参数、纠错/失败重试策略的正式确认。

这些不否定 adapter 的运行可用性，但使整体成熟度保持
`PERSON_A_INTEGRATED_DEVELOPMENT`。
