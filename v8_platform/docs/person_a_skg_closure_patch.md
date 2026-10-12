# Person-A SKG Final Closure Patch

日期：2026-09-13。范围仅限 Probe profile 隔离、confirm 双方提交和 rekey 并发协调；
V8 主事件架构与 A 上游密码实现均未重构。

## 问题与结果

| Issue | 修改前反例 | 正确语义与实现 | Acceptance | Status |
|---|---|---|---|---|
| SKG-PROBE-PROFILE-001 | 融合版把原 V8 单高斯 latent 全局改为 ±8 dB 双状态，使所有 Probe 被 A v0.1 compatibility 参数污染 | `ProbeService` 默认逐值恢复原 V8 `V8_DEFAULT`；双状态仅以显式 `PERSON_A_V01_COMPAT_TEST` 存在，run metadata/fingerprint 记录且阻塞 formal readiness | A31 | CLOSED |
| SKG-CONFIRM-2PC-001 | 任一 CONFIRM 到达即调用 A `apply_confirm_blob()`，可能单边 `KeyProvider.put()` | authenticated confirm 先进入 pending；两端均收到并 cross-verify 后才 `COMMIT_READY` 并成对 commit；异常回滚新 epoch | A28/A30 | CLOSED |
| SKG-REKEY-RACE-001 | pair/session 索引无 target epoch，直接 `initiate_session()` 又无去重，可创建重复 SKG | `RekeyCoordinator` 唯一键 `(sorted_pair, session, target_epoch)`；active handshake 重复请求返回 `existing_rekey_in_progress` | A29 | CLOSED |

## Probe 差异证据

相同 seed=31、run ID、64 samples：

| Profile | Endpoint A std/range | Endpoint B std/range | 用途 |
|---|---:|---:|---|
| `V8_DEFAULT` | 1.244 / 5.123 dB | 1.296 / 6.065 dB | 原 V8 默认、正式仿真/calibration/攻击 |
| `PERSON_A_V01_COMPAT_TEST` | 7.896 / 18.325 dB | 8.010 / 18.719 dB | A v0.1 adapter 联调，TEST_ONLY |

固定反例中，`V8_DEFAULT` 的 A v0.1 handshake 保守失败为
`SKG_RECONCILE_MISMATCH` 且双方 MISSING；compat profile 的状态链为：

```text
NEGOTIATING → CONFIRM_PENDING → COMMIT_READY → AVAILABLE
```

这一区别现在被诚实保留，不再用 compatibility 成功率代表真实 V8 channel compatibility。

## 双方提交不变量

1. 一个 confirm 到达时只保存经过 Ed25519 验证的 public blob。
2. `pending_confirm_blobs` 和两端本地 `generated_confirm_blobs` 未齐全时，不调用 A commit。
3. 任一 cross-confirm 不同即 `SKG_CROSS_CONFIRM_CONFLICT`，双方无新 epoch。
4. 两端一致后进入 `COMMIT_READY`；两个 A result 的 epoch/key ID 必须一致。
5. 意外 commit error 会 revoke 双方 target epoch 并移除 B references。
6. timeout/失败不撤销旧 epoch；A28 证明 epoch 1 ciphertext 仍可 decrypt PASS。

## 实际测试

| Suite | Result |
|---|---:|
| A upstream | 34 passed |
| Original V8 | 355 passed, 2 dependency warnings |
| Person-A integration (原 36 + A28–A31 5 cases) | 41 passed |
| Combined platform | 396 passed, 2 dependency warnings |

Warnings 为 FastAPI/Starlette TestClient 的第三方 deprecation warning，不是 SKG 失败。
A 的 `aead.py`、`key_provider.py`、`skg.py`、`identity.py`、`credentials.py` 均未修改。

## 状态

- AEAD integration：READY
- SKG adapter/network/two-phase baseline：READY（compat TEST profile）
- SKG on V8 default/real RF：NOT FORMALLY VALIDATED；A-CHANGE-001 / real-data dependency
- Identity：READY（integration-test identity；formal asset external）
- Credential：READY（simulated fingerprint；formal asset external）
- Rekey：READY（single active negotiation + pair commit）
- Five-attack regression：PASS
- Formal experiment：BLOCKED_EXTERNAL
