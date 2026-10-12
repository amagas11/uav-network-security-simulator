# V10 Final Scenario Mechanism Matrix

本矩阵由 `tests/acceptance/test_final_scenario_mechanism_matrix_v6.py` 使用当前 V10
runtime 确定性运行。当前攻击合同不包含 DOS/JAMMING，因此矩阵为 21 个场景。每行
同时要求 DatasetValidator、LeakageAudit 与 mechanism-specific assertions 通过。

| Scenario | Dataset | Mechanism | Injected | Reached | Business executed | Security result | Actual evidence | Leakage | Result |
|---|---:|---:|---:|---:|---:|---|---|---:|---:|
| NORMAL_BASELINE | valid | yes | N/A | yes | yes | normal delivery | TX=3, RX=3 | pass | PASS |
| NORMAL_LOW_SNR | valid | yes | N/A | N/A | N/A | no attack label | samples=10, attenuation=55 dB, min SNR=-17.0961 dB | pass | PASS |
| NORMAL_PACKET_LOSS | valid | yes | N/A | N/A | N/A | no attack label | loss=1.0, RX_FAILURE=4 | pass | PASS |
| NORMAL_TRAFFIC_BURST | valid | yes | N/A | N/A | N/A | no attack label | generated=36, max queue=6, max rate=36 pps | pass | PASS |
| NORMAL_OUT_OF_ORDER | valid | yes | N/A | yes | yes | PASS/PASS/PASS | seq=100,102,101 accepted inside window | pass | PASS |
| NORMAL_STATE_CHANGE | valid | yes | N/A | yes | yes | no attack label | node2 battery=88%, CRUISE, consistent telemetry | pass | PASS |
| NORMAL_CONGESTION | valid | yes | N/A | N/A | N/A | no attack label | generated=48, max queue=8, busy +.65, rate=48 pps | pass | PASS |
| SPOOFING_UNKNOWN_ID | valid | yes | yes | yes | no | UNKNOWN_DEVICE_KEY / DROP | claimed=999, actual External, HMAC failures=7 | pass | PASS |
| SPOOFING_KNOWN_ID_CONFLICT | valid | yes | yes | yes | no | HMAC_MISMATCH / DROP | claimed GCS0, actual External, failures=7 | pass | PASS |
| EAVESDROPPING_NONSENSITIVE_PLAINTEXT_CONTROL | valid | yes | yes | yes | N/A | ordinary plaintext, not exposure | captures=3, exposure=0 | pass | PASS |
| EAVESDROPPING_CIPHERTEXT_ONLY | valid | yes | yes | yes | N/A | AES-GCM protected | captures=3, ciphertext=3, exposure=0 | pass | PASS |
| EAVESDROPPING_PLAINTEXT_EXPOSURE | valid | yes | yes | yes | N/A | sensitive exposure control | captures=3, plaintext exposure=3 | pass | PASS |
| DOS_FLOODING | valid | yes | yes | yes | no | receiver rate alert + HMAC DROP | generated=84, observed=84, max rate=72 pps, HMAC rejected=84 | pass | PASS |
| FDI_COMMAND_REPLACEMENT | valid | yes | yes | no* | no | HMAC_MISMATCH / DROP | HMAC then FLY_TO→LAND; blocked at intermediate receiver | pass | PASS |
| FDI_TELEMETRY_ABRUPT_CHANGE | valid | yes | yes | yes | no | HMAC_MISMATCH / DROP | 3 mutations, altitude 100→150 | pass | PASS |
| FDI_TELEMETRY_GRADUAL_DRIFT | valid | yes | yes | yes | no | HMAC_MISMATCH / DROP | 3 mutations: 105,110,115 | pass | PASS |
| FDI_OUT_OF_RANGE_VALUE | valid | yes | yes | yes | no | HMAC_MISMATCH / DROP | 3 mutations, altitude=5000 | pass | PASS |
| FDI_LOGICAL_INCONSISTENCY | valid | yes | yes | yes | no | HMAC_MISMATCH / DROP | 3 mutations, altitude=120 + LANDED | pass | PASS |
| REPLAY_IMMEDIATE_REPLAY | valid | yes | yes | yes | no | HMAC PASS → DUPLICATE | capture=.2 s, replay=.6 s, same message/tag | pass | PASS |
| REPLAY_DELAYED_REPLAY | valid | yes | yes | yes | no | HMAC PASS → replay rejection | capture=.2 s, replay=.8 s, configured delay=.6 s | pass | PASS |
| REPLAY_OLD_SESSION_REPLAY | valid | yes | yes | yes | no | HMAC PASS → WRONG_SESSION | rotation=.6 s, old replay=.8 s | pass | PASS |

`*` COMMAND_REPLACEMENT 的 GCS→Follower 多跳帧在 Leader ingress 已被端到端 HMAC gate
拒绝，未到最终业务 target；这是正确的前置止损。其它一跳 FDI 的 `reached_target=true`
只表示 PHY decode 到达 receiver，不等于业务执行。

## Gate interpretation

- HMAC 失败只输出 observer-local `AUTH_FAILURE`，攻击类型归属只在离线 episode truth。
- Flooding 的 rate 统计发生在 HMAC DROP 之前，并按 receiver 所有来源聚合。
- FDI modification stage 为 `POST_HMAC_PRE_TRANSMISSION`，tag 不重算。
- Replay 保持原 frame 的 HMAC/tag/timestamp/sequence/session；HMAC 必须先 PASS。
- normal 场景不创建 attack label。
- 审计结论仅为：当前规则型与统计型 leakage audit 未发现验收范围内的明显 shortcut。

当前实测：21/21 scenario contract + mechanism + leakage gates PASS。
