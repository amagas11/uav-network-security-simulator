# 需求冲突记录

审计日期：2026-09-28（V10 五类攻击 HMAC closure）。

未发现阻塞实施的实质冲突。以下差异按工程化细化处理：

| Sources | Difference | Classification | Adopted resolution | Compatibility impact |
|---|---|---|---|---|
| C 需求 `runs.jsonl` 示例 vs 工程实施规范 §21/§32 | 示例使用 `calibrated_simulation`；当前仓库没有可核验真实校准数据 | 示例与当前事实，不是实质冲突 | 当前固定 `data_source.kind=simulation`、`calibration_status=UNCALIBRATED_BASELINE`；只有加载有来源 profile 后才能升级 | 无 schema 破坏 |
| 当前冻结指令 vs 历史 C/规范 DoS 两子类 | 当前明确 DoS 只保留 Flooding | 后续冻结语义覆盖旧工程细化 | `attack_family=DOS` 只接受 `FLOODING`；旧 subtype fail-fast，legacy DoS 统一映射 Flooding | 当前 schema/API/UI 不再公布被取消 subtype |
| C §4.2 禁止 `defense_action` 作为原始特征 vs C §3.1 要求 `DEFENSE_RESULT` 事件 | 一个禁止回填原始 observation，一个要求独立结果事件 | 不是实质冲突 | 原始 TX/RX/PHY event 不含结论；动作只作为后续 `DEFENSE_RESULT` event | V1 语义明确化 |
| A 文档 role=`tx/rx` vs “每端测量自己收到的信道” | 探测中 TX 端也需本地观测 | 需要协议解释但不阻塞 | 一次 probe 包含双向相邻 sounding；role 表示配对轮次角色，两端 observation 均由各自接收链独立测得 | A 适配器按原字段不变 |
| 旧代码/API vs 新持续 AttackPlan/run lifecycle | 旧前端围绕下一帧攻击 | 当前代码不符合新需求 | 新 API/内核采用 plan；旧 `/api/attack` 转换为短时 plan，`/api/step` 仅 debug | 保留兼容层并在迁移文档说明 |

若后续 A/C 正式交付改变冻结字段或语义，应新增记录并按
`docs/schema_version_decision_v5.md` 的版本规则迁移，不能静默修改冻结契约。

V4 没有发现新的实质冲突。FDI 的 attacker=compromised sender、target=business
receiver，normal plan 仅属 offline provenance，以及 passive eavesdropping 不进入
普通 detection confusion matrix，均是对 C 原始语义的落实，不是对原需求的改写。

V5 同样没有发现新的实质冲突。可信 defense target、target-side attack outcome、
recent-window sequence gap、single-target fail-fast 与 legitimate/external participant
拆分，是对原始身份、局部观测、数据统计和可追溯要求的严格化。packet-size 与
gap 的既有冻结语义发生更正，因此按兼容规则显式升级 schema 2.0→3.0，而非静默
重解释历史数据。
