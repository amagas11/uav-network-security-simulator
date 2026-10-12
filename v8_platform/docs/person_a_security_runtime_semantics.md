# Person-A Security Runtime Semantics

## 会话与状态

密钥索引是 `(local_id, direct_peer_id, business_session_id, key_epoch)`。Probe 必须使用
同一个 business session；默认 V8 probe session 生成仅用于非 A 调用的向后兼容路径。

```text
MISSING
  └─ initiate/session-required → NEGOTIATING
       └─ signed reconcile delivered → CONFIRM_PENDING
            ├─ both signed confirms received and cross-verified → COMMIT_READY
            │    └─ both A providers commit → AVAILABLE
            └─ missing/bad identity/mismatch/timeout → FAILED (no new key on either side)
AVAILABLE(epoch n)
  └─ REAUTH_REKEY_REQUEST → UPDATING
       ├─ network SKG complete → AVAILABLE(epoch n+1)
       ├─ pre-commit failure/timeout → FAILED; no new epoch
       └─ partial commit exception → rollback recorded valid epoch n → FAILED
```

`request_rekey.success=true` 表示协商请求被接受，不表示 key 已更新；
`new_key_epoch=null` 与末状态 `UPDATING` 是异步语义。完成后 coordinator 才更新双方节点
epoch。旧 ciphertext 是否可在过渡期解密完全服从 A KeyProvider 的原实现。

## Probe profile 冻结

- `V8_DEFAULT`：原始 V8 单高斯 reciprocal fading（标准差参数 1.25 dB）及独立端噪声；
  是默认值，用于正式仿真、calibration、五类攻击和未来真实无线扩展。
- `PERSON_A_V01_COMPAT_TEST`：为 A v0.1 的 exact-match mean-threshold quantizer 保留的
  双状态（约 ±8 dB）联调 profile。它必须由 `PersonASecurityBundleFactory` 显式选择，
  metadata 标记 TEST_ONLY，并加入 `PERSON_A_COMPAT_PROBE_TEST_ONLY` readiness blocker。

更改 profile 会进入 run semantic fingerprint。兼容 profile 的 SKG 成功只证明 adapter、
消息传输与提交状态机可运行，不证明 A v0.1 与原始 V8/真实信道兼容。

## 双方确认与 rekey 并发

接收一侧 CONFIRM 时，B 只缓存已经 Ed25519 验证的 public confirm；不调用 A
`apply_confirm_blob()`。只有两端 confirm 都到达并与两端本地 expected confirm 一致后，
状态才进入 `COMMIT_READY`，随后调用双方 A engine。rekey 开始前 transaction context
分别记录两端实际可用的 previous epoch。若提交阶段出现异常/不一致，adapter 调用 A 的
公开 `rollback_epoch()`：撤销/阻断 target epoch，并仅在 previous epoch 此刻仍合法时把
它恢复为 A provider 的 outbound current；B coordinator reference、runtime node epoch 和
A provider 实际 encrypt epoch 同步恢复。若 previous 已过期/撤销或不存在，则保持 key
unavailable，绝不复活非法 key。因而不存在“单端 confirm 到达即拥有新 key”或
“B 显示 epoch n、A 实际继续选 revoked epoch n+1”的路径。

`RekeyCoordinator` 以 `(sorted_node_pair, session_id, target_epoch)` 为唯一键。
`NEGOTIATING/CONFIRM_PENDING/COMMIT_READY/UPDATING` 期间的重复请求返回
`existing_rekey_in_progress`，沿用原 probe，不创建第二个 SKG 或同 epoch key。

## AAD 与方向

`build_aad()` 是 protect/open 的唯一 canonical serializer，JSON UTF-8、keys sorted、
compact separators。字段：message ID、claimed src/dst、packet type、sequence、session、
epoch、hop sender/receiver、内部 link ID、hop index。任何字段或方向变化都会使 GCM
认证失败。

## 状态映射

| A result | V8 status/auth | key state | payload |
|---|---|---|---|
| `ok` | `OK/PASS` | `AVAILABLE` | decoded business object |
| `auth_fail` | `ERROR/FAIL` | `AVAILABLE` | null |
| `key_unavailable` | `UNAVAILABLE/UNAVAILABLE` | `MISSING` | null |
| `key_expired` | `ERROR/FAIL` | `EXPIRED` | null |
| `nonce_reuse` | `ERROR/FAIL` | `FAILED` | null |
| identity/signature failure | `ERROR/FAIL` | `MISSING` | null |
| unprotected explicit control | `OK/PASS` | `UNAVAILABLE` | plaintext, with development reason |

发送侧 `key_unavailable/key_expired` 通过 `CryptoProtectionError` 进入可恢复 runtime 分支：
敏感明文不发送，事件用 `withheld_message_ref` 关联原消息，不伪造 TX。

## SKG control 安全边界

RECONCILE/CONFIRM blob 是公开协议材料，但必须绑定 src、dst、session、probe 并经 A
IdentityStore Ed25519 签名。接收端先验签，失败不得调用 `apply_*_blob` 或 commit key。
SKG_CONTROL 在最终 hop 由 security handler 消费，不进入 business delivered queue。

C online event 仅看到 control protocol、phase、public length、auth/key state；完整 blob、
signature 与 public PEM 不作为模型 feature。Simulator 内部仍保留传输 payload，才能真实
验证网络损坏/丢失/身份绑定。

## Terminal credential

仿真将公开 `TerminalProfile.public_fingerprint()` 编码为 bytes；这是
`SIMULATED_TERMINAL_FINGERPRINT`，不是硬件指纹。A CredentialService 的 derived serial
只留在 adapter 内存；PROGRAM_START、NETWORK_JOIN、SENSITIVE_COMMAND 只输出 allow/deny、
credential ID 与 failure reason。复制/篡改 profile 会改变 fingerprint 并导致拒绝。

## Fail-closed 原则

- A package 不可用：只有显式 Person-A mode 失败；不静默 fallback mock。
- key 不可用：不发送敏感 plaintext，不 crash，不假造 key。
- SKG 观测/网络/身份失败：双方都不得出现 AVAILABLE。
- AEAD failure：不返回业务 payload、不执行 business handler。
- GCM PASS 只证明密文完整与持钥身份，不代表 FDI payload 合理，也不绕过 ReplayWindow。
