# Person-A Crypto Integration

## 结构

```text
person_a_crypto/upstream/crypto  (single upstream source)
              │
              ▼
swarm_sim.integrations.person_a
  ├─ PersonASecurityBundleFactory
  ├─ PersonAKeyCoordinator
  ├─ PersonACryptoProvider
  ├─ PersonATerminalAuthorizerAdapter
  └─ PersonASecretLeakageAudit
              │
              ▼
RuntimeDependencies.security_bundle_factory
              │
              ▼
PlatformRuntimeFactory → Direct / Manager / FastAPI / Batch / RL
```

Person-A 源码唯一保存在平台同级 `person_a_crypto/upstream/`。platform 的 packaging config
不会把它打进 `swarm_sim`；adapter 以明确路径加载独立 package。每次 factory create/reset
构建全新的 bundle，避免 key、nonce、SKG 或 credential state 跨 run 污染。

## 使用示例

```python
from pathlib import Path
from swarm_sim import PlatformRuntimeFactory, RunConfig, RuntimeDependencies
from swarm_sim.integrations.person_a import PersonASecurityBundleFactory

bundle_factory = PersonASecurityBundleFactory(
    Path("../person_a_crypto/upstream"),
    skg_timeout_s=3.0,
    # Default is V8_DEFAULT. Integration-only A v0.1 tests must opt in:
    # probe_profile="PERSON_A_V01_COMPAT_TEST",
    # Formal startup can also supply identity_store_factory and
    # credential_service_factory; secret material stays inside those closures.
)
factory = PlatformRuntimeFactory(
    RuntimeDependencies(security_bundle_factory=bundle_factory)
)
runtime = factory.create(RunConfig(seed=42, auto_traffic=False))
```

测试可显式传 `test_only_preloaded_keys` 验证 AEAD adapter；该入口名称、docstring 和
provenance 均明确 TEST ONLY，不能作为 SKG 完成证据。正式集成测试则调用
`runtime.security_coordinator.initiate_session(...)`，让 Probe、RECONCILE 与 CONFIRM
真实经过 V8 网络。

## 业务与协商闭环

1. 敏感业务无 key：packet withheld，产生可解释 AUTH_RESULT，并启动同一 session SKG。
2. V8 Probe 生成两端独立本地观测；adapter mapping 到 A 类型。
3. 两端 A engine 分别形成 RECONCILE；Ed25519 签名后作为 SKG_CONTROL 入队。
4. peer 经 V8 PHY 接收、验签、apply，并生成签名 CONFIRM；同样经网络返回。
5. B 先缓存两端 confirm；只有双方均收到且 cross-confirm 一致才进入 `COMMIT_READY`。
6. 两个 A engine 随后成对 commit；V8 节点 epoch 只在双方成功后更新。
7. 单侧丢失、cross-confirm 冲突或 timeout 均为 FAILED，双方无新 epoch，旧 epoch 保留。
8. 若双方 cross-confirm 后第二端 commit 异常，A 的公开 `rollback_epoch()` 将第一端
   outbound current 恢复到 transaction 中记录的合法 previous epoch；invalid old key
   不会复活。
9. 同 pair/session/target epoch 的重复 rekey 返回 `existing_rekey_in_progress`。
10. 后续敏感业务调用 A KeyProvider.encrypt/decrypt；Frame 只带公开密码材料。

## Portable delivery

最终包 canonical root 是 `V8_PERSON_A_FINAL/`，仅含 `v8_platform/` 与唯一
`person_a_crypto/upstream/`。所有目录组件均为 ASCII；原始中文文档文件名由标准 ZIP
UTF-8 filename flag 保存。integration discovery 不依赖当前工作目录或中文路径。构建器
排除 `__pycache__`、`.pytest_cache`、pyc、work/debug artifacts，并用 Python 默认
`ZipFile.extractall()` 做 fresh-extraction smoke。

## Probe profile

`V8_DEFAULT` 是所有 runtime 的默认值，行为与未融合原始 V8 一致。A v0.1 exact-match
算法的联调测试显式选择 `PERSON_A_V01_COMPAT_TEST`；它保留融合初版的 ±8 dB 双状态
reciprocal sampling，仅用于证明 SKG adapter/network/commit 闭环。run record 写入
`probe_profile`，compat 模式强制产生 formal-readiness blocker，不能用于 calibration 或
正式实验结论。

## 攻击组合

- Spoofing：EXTERNAL 无合法 provider；声称 GCS 身份仍无法认证，不触发误隔离。
- Eavesdropping：加密敏感流量只暴露 ciphertext；显式未保护敏感开发控制仍保留正样本。
- Flooding：queue/load 机制不因 crypto adapter 改义；generic PHY loss/interference 仍可用于 SKG 链路失败测试，但当前攻击合同不再提供 JAMMING。
- FDI：合法失陷节点在 pre-crypto 修改业务值，再由 A 正常加密，接收端 AEAD 可 PASS，
  业务异常仍由规则/模型检测。
- Replay：重放保留原 ciphertext/nonce/message ID，A AEAD 可能 PASS；B ReplayWindow 仍按
  duplicate/delay/session lifecycle 拒绝。
- 外部 ciphertext/nonce/AAD tamper：A 返回 auth failure，payload null，business handler
  不执行。

## 非秘密输出

允许：algorithm、nonce、key ID/epoch、auth/key state、公开身份材料、SKG phase 与 public
blob length。禁止：raw key、private PEM、credential master/serial、SKG quantized bits、
candidate key、privacy-amplification intermediate。完整 reconciliation/confirmation blob
只在 runtime control payload 内传递，不复制到 C online features。

## 成熟度

本集成证明 A library 能真实进入 V8 软件路径，并已关闭 half-key 与重复 rekey；不证明
A v0.1 在 `V8_DEFAULT` 或实测信道上的成功率，也不证明联调身份/credential 是正式资产。
当前状态固定为 `PERSON_A_INTEGRATED_DEVELOPMENT`，集成软件 baseline ready，最终正式
实验仍为 `BLOCKED_EXTERNAL`。
