# Person-A Change Requests

最终 polish 发现 A v0.1 的公开 `put()/revoke()` 生命周期不能完整撤销“第一端已经
commit、第二端 commit 抛异常”的 rekey transaction：`revoke()` 不会把 outbound
current epoch 恢复到旧 key。集成补丁因此只在 `crypto/key_provider.py` 增加一个不暴露
key material 的生命周期 API；密码算法、SKG、Identity 与 Credential 均未修改。

## A-CHANGE-001 — reciprocal noise tolerance / reconciliation policy

- 问题：A v0.1 只比较 8-byte syndrome 是否完全相等，没有纠错/容差。
- 复现：固定 seed/run 下使用 `V8_DEFAULT` reciprocal observation，双方各自量化后，
  network RECONCILE 返回 `SKG_RECONCILE_MISMATCH`；任一端均不 commit key。
- 当前行为：显式 `PERSON_A_V01_COMPAT_TEST` 可完成 adapter 联调，但该 profile 是
  TEST_ONLY，并写入 formal-readiness blocker。
- 期望：人员 A 基于最终批准 reciprocal measurements 定义纠错、信息协调或保守失败/
  retry 参数，使实现与其安全预算一致；不得要求 B 修改正式信道统计来制造 exact match。
- 为什么不能只靠 B adapter：改变 syndrome 接受规则或恢复不一致 key bits 属于 A 的
  密码/SKG 语义，B 不应猜测或重写。
- 影响：不阻塞 AEAD/Identity/Credential、网络化 SKG 状态机及
  `INTEGRATED_DEVELOPMENT` baseline；阻塞真实信道 SKG 成功率和 FORMAL 结论。

状态：`OPEN_EXTERNAL_A`。本轮明确不处理。

## A-CHANGE-002 — failed rekey epoch rollback lifecycle API

- 问题：`KeyProvider.put(epoch=2)` 后 `current_epoch=2`；随后 `revoke(epoch=2)` 只标记
  record revoked，未来 `encrypt()` 仍选择 epoch 2 并返回 `key_unavailable`，即使合法
  epoch 1 material 仍在。
- 原始反例：双端 epoch 1 正常；node 1 commit epoch 2 成功、node 2 commit 抛异常；旧
  ciphertext 可解密，但 node 1 的全新 outbound traffic 无法加密。
- 为什么 B adapter 不能单独修复：A `encrypt()` 不接受指定 epoch，B 又禁止访问
  `_LinkState/_KeyRecord.material`；仅调整 B reference 无法改变 A 的实际 outbound current。
- 最小扩展：`KeyProvider.rollback_epoch(peer_id, session_id, *, failed_epoch,
  restore_epoch, sim_time_s=None)`。它撤销 failed epoch，且仅在记录的 previous epoch
  当前仍为 `ok` 时恢复 outbound current；不存在/过期/已撤销 key 不会被复活。
- Secret boundary：输入和返回只有 peer/session/epoch、key handle/status；没有 raw key。
- 修改范围：仅 `crypto/key_provider.py` 和相应 provider tests；AES-GCM、SKG
  quantization/reconciliation、Ed25519、Credential 均不变。
- 验证：A provider unit tests 37 passed；集成 A32–A35 验证异常 rollback 双向新流量、
  三层 epoch 一致、invalid previous 不复活及正常 rekey 不回归。

状态：`REQUIRES_PERSON_A_ACCEPTANCE`。集成 baseline 已验证，但此上游 API 扩展仍应由
人员 A 在下一次正式库发布中确认/吸收。

## 非阻塞后续确认

| ID | 类型 | 内容 | 当前处理 |
|---|---|---|---|
| A-FOLLOWUP-001 | REAL-DATA VALIDATION | 用最终批准的 reciprocal measurements 验证 A-CHANGE-001 的成功率、安全预算与失败/retry policy | 默认已恢复 V8_DEFAULT；compat profile 仅作 TEST_ONLY integration fixture |
| A-FOLLOWUP-002 | ASSET LIFECYCLE | 正式 Ed25519 私钥、trust root、credential master 的加载/轮换/安全存储格式尚未交付 | factory 已提供 programmatic 注入边界；联调使用显式 TEST-only generated material |
| A-FOLLOWUP-003 | VERSIONING | A package 未暴露机器可读 release/bundle version | provenance 暂按交付契约记录 `person-a-0.1`；正式交付时建议提供公开版本/hash，不影响密码语义 |

以上是外部资产/真实数据阶段事项，不需要 B 修改 A 算法，也不构成本轮已知 P1 adapter bug。
