# V11 Remaining Closure

本补丁只关闭 Evaluation 防御归因、Flooding ingress/emitter 和正式 Web Person-A
composition root 三个已确认缺口。Person-A upstream、CSI 模型、五类攻击构造、Replay
顺序、Calibration、RL、C 数据合同及通用 PHY 均未重构。

## 修改前反例

| Counterexample | Actual V11-before behavior |
|---|---|
| Spoofing evaluation | Runtime `AUTH_FAILURE → DROP_PACKET executed=true`；evaluation `action_executed=false`, `defense_effective=false`, attempts empty |
| FDI evaluation | 同上；POST-HMAC 100.0→100.1 已被 runtime 阻断但 evaluation 仍 false |
| Flooding 80 pps, step .2, TX budget 4, end .6 | generated/queued 32；仅 28 次 TX，20 次发生在 end 后；receiver normal RX queue 峰值 16；run 结束仍有 4 条 attacker TX backlog |
| Official application | `MockKeyProvider(TEST_ONLY_NOT_SKG)` + `TestOnlyAeadCryptoProvider(TEST_ONLY_AEAD_NOT_SKG)`；无 security coordinator |

修改前基线：compileall PASS；platform **398 passed / 2 warnings**；Person-A upstream
**37 passed**。

## 文件范围

- Runtime/code：`swarm_sim/runtime.py`、`swarm_sim/domain.py`、
  `swarm_sim/evaluation.py`、`app/app.py`。
- Tests：新增 `tests/acceptance/test_v11_remaining_closure.py`；按新 Flooding 合同更新
  `tests/regression/test_v3_audit_regressions.py` 的旧 backlog 反例。
- Docs：`README.md`、`docs/runtime_dependency_integration.md`、
  `docs/requirement_traceability_matrix.md`、`docs/test_report.md`、
  `docs/final_status_report.md` 及本文件。
- 删除源码文件：无。Person-A upstream diff：0 files。

## 实现

### Evaluation

`ExperimentEvaluator` 统一维护 offline attribution label set。Spoofing/FDI episode 可接收
自身 family 或 generic `AUTH_FAILURE`；防御匹配另允许 `RL_RECOMMENDATION`。这是离线 join，
online detector 仍不读取 attack ID/family/truth。

### Receiver path

```text
PHY decode success
  → receiver-total record_arrival / DOS aggregate detection
  → plaintext application-HMAC pre-ingress gate
      FAIL → one AUTH_RESULT → one DROP_PACKET → no normal rx_queue
      PASS → cache non-secret verification result → normal rx_queue
  → RX service reuses cache
  → timestamp / session / ReplayWindow / business processing
```

Encrypted Eavesdropping frames are not interpreted before decryption；它们继续在 RX service
中执行 Person-A AES-GCM open 后再验证应用 HMAC。`SKG_CONTROL` 继续由 Ed25519 控制面
认证，不进入业务 HMAC pre-gate。每帧最多产生一组 AUTH/DEFENSE 事件和一次 drop count。

### Flooding emitter

`pps × step_s` 个恶意 Message 在 active tick 内立即进入原有 `_transmit_intent()`，所以仍
完整经过 CryptoProvider plaintext frame、route/link、PHY、RX_SUCCESS/RX_FAILURE、receiver
arrival stats 和 HMAC gate；只绕过合法应用 TX queue service quota。不存在跨 tick attack
queue，因此 end 后无旧 Flooding backlog，正常节点的 queue capacity/TX/RX budget 未改变。

### Formal Web Person-A

`build_application_runtime_factory()` 以 `app/app.py` 为锚点解析
`../person_a_crypto/upstream`，注入 fresh `PersonASecurityBundleFactory`。profile 为
`V8_DEFAULT`，预加载 key 数为 0。裸 Direct/unit factory 仍保留 test provider 默认。
正式 run provenance 继续标记 `PERSON_A_INTEGRATED_DEVELOPMENT`，不冒充 formal A asset。

## 手工运行证据

### Spoofing / FDI

| Family | Runtime reason/action/executed | Evaluation action/effective |
|---|---|---|
| SPOOFING | AUTH_FAILURE / DROP_PACKET / true | true / true |
| FDI | AUTH_FAILURE / DROP_PACKET / true | true / true |

### Flooding

配置：80 pps、step .2、queue 32、TX budget 4、RX budget 2、active ticks .2/.4/.6。

| Metric | Actual |
|---|---:|
| generated / transmitted / TX events | 48 / 48 / 48 |
| decoded RX arrivals | 48 |
| max receiver-total rate | 49.0 pps（含 1 条合法业务） |
| HMAC rejected malicious | 48 |
| max normal RX queue | 1（唯一合法帧；恶意帧为 0） |
| legitimate delivered | true |
| attacker TX backlog at end | 0 |
| attack TX / RX at-or-after end | 0 / 0 |

### Official FastAPI Eavesdropping

| Evidence | Actual |
|---|---|
| key / crypto provider | PersonAKeyCoordinator / PersonACryptoProvider |
| Probe profile / preloaded key count | V8_DEFAULT / 0 |
| SKG_CONTROL TX / RX | 4 / 4 |
| handshake | AVAILABLE |
| encrypted sensitive TX | 16 |
| capture / ciphertext | 17 / 15 |
| plaintext exposure / content recovery | 0 / 0 |

## Regression

- Focused T1–T12: **12 passed**.
- Full pytest: **410 passed, 0 failed, 0 skipped, 2 warnings**.
- Person-A upstream: **37 passed**；integration: **46 passed**；CSI: **4 passed**。
- Current scenario mechanism matrix: **22 passed**；DatasetValidator/LeakageAudit/C data
  focused gates: **44 passed**。
- Frontend: `npm ci` PASS（306 packages；13 dependency advisories，未做 breaking force-fix）；
  `npm run type-check` PASS；`npm run build-only` PASS。
- Person-A upstream files changed by this patch: **none**。

Final result: **READY**。Formal A identity/credential assets、real-RF SKG validation、approved
real calibration data 和 C trained assets 仍是诚实的 external maturity boundary。
