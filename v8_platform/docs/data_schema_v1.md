# 数据契约 3.2（V10 五类攻击语义闭环）

`schema_version=3.2.0`。文件名 `data_schema_v1.md` 仅为历史引用兼容，不代表当前 schema 版本。编码统一为 UTF-8；JSONL 每行一个完整 JSON 对象；协议时间统一使用 `sim_time_s`（秒）。缺失值使用 JSON `null`，并由相邻 `availability`/`missing_reason` 解释；数值 `0` 始终表示一次有效测量。V10 本轮只增加 optional 应用层 HMAC 观测和 RunConfig 字段，未改变 schema major。

V5 因 packet-size、sequence-gap、resolved plan/outcome 与 participant 边界的 breaking change 提升到 `3.0.0`；V6 为 `3.1.0`。V7 不改变核心事件类型/单位，新增 calibration controls、model assets 与 layered readiness 的 optional run 字段，因此提升 minor 至 `3.2.0`。完整判断见 `docs/schema_version_decision_v7.md`，C loader 合同见 `docs/schema_contract_for_C.md`。

机器可读的唯一契约是 `dataset/schema.json`。主要对象均逐字段声明 `name`、`type`、`required`、`nullable`、`description`、`semantic_id`，适用时还声明 `unit`、`enum`、数值范围、正则和 nested reference：

- `runs`、`RunConfig`、`RunProfiles`、`DataSourceProvenance`、`CalibrationProfile`、`CalibrationParameter`、`CalibrationDatasetManifest`、`AttackPlan`、`NormalDisturbancePlan`
- `events`、`labels`、`rf_manifest`、`model_result`、`LocalPhyObservation`
- `online_features.packet`、`phy`、`traffic`、`node_state`、`topology`、`security_state`、`resource_state`

## 目录结构

```text
run-directory/
├── schema.json
├── runs.jsonl
├── events.jsonl
├── labels.jsonl
├── rf_manifest.jsonl
└── rf_samples/
```

## `runs.jsonl`、完整实验计划与 calibration provenance

每次运行一条记录，必含唯一 run ID、seed、duration/step、节点与角色、逻辑起始时间、软件版本、完整无秘密 RunConfig、完整攻击/正常扰动计划、计划 ID、语义配置指纹、profile 以及数据/校准来源。`seed` 控制随机过程但不是 run identity；重复 seed 的多个实验必须有不同 run ID/目录。未加载可核验 calibration profile 时固定为：

```json
{
  "data_source": {
    "kind": "simulation",
    "source_dataset_version": null,
    "calibration_version": null
  },
  "profiles": {
    "channel_profile_id": "uncalibrated-static-a2a-v1",
    "attack_plan_id": null,
    "normal_disturbance_plan_id": null
  },
  "calibration_status": "UNCALIBRATED_BASELINE"
}
```

加载 `CalibrationProfile` 后，`source_dataset_version`、`calibration_version`、`channel_profile_id` 来自 profile provenance；run 同时保存完整 profile、source manifest、sample count、method、quality/warnings、profile hash、maturity、实际 runtime controls 和 parameter semantics。fitter 给出 RSSI/SNR/loss/latency descriptive targets，并派生 `rssi_bias_db`、`snr_bias_db`、`background_loss_probability`、`base_latency_ms`、`latency_jitter_ms`；这些控制真实 PHY。`throughput_mean_mbps` 当前为 descriptive validation target，runtime throughput 由 bandwidth/SINR/PER 间接产生。Runtime/Batch/FastAPI/RL 使用同一 profile。测试 synthetic metadata 不冒充真实测量。来源枚举为 `simulation`、`calibrated_simulation`、`real_measurement`、`augmented_real`。

run 还包含 `model_assets`（bilstm/dueling_q/rff 每槽位 configured/name/version/start/export status/error 与可用 bundle provenance）、`readiness_components`、`readiness_blockers` 和 `dataset_readiness`。即使模型零输出也记录 provenance。`experiment_readiness` 只表示 final formal integrated experiment；它与 dataset 是否可供 C 开发训练分开。

`config_fingerprint` 是 canonical JSON 的 SHA-256，输入包括完整 RunConfig、攻击参数、正常扰动参数、profile/calibration reference、software/schema version。run-scoped `attack_id`/`profile_id` 不参与语义 hash，因此同配置同 seed 可复现；例如 FDI `delta_per_step=5` 与 `50` 必然不同。

## `events.jsonl`

事件外层固定包含：

- `schema_version`、`run_id`、`event_id`、nullable `message_id`、`sim_time_s`
- `event_type`、`observer_node_id`、`observer_role`
- `online_features`、`availability`、`extensions`

事件类型为 `TX`、`RX_SUCCESS`、`RX_FAILURE`、`PHY_SAMPLE`、`QUEUE_SAMPLE`、`NODE_STATE`、`TOPOLOGY_UPDATE`、`AUTH_RESULT`、`MODEL_RESULT`、`DEFENSE_RESULT`。每个物理 hop 产生新的 TX/RX `event_id`；同一业务消息（包括 replay）保持原 `message_id`。

`online_features` 固定含七组 observer-local 字段：`packet`、`phy`、`traffic`、`node_state`、`topology`、`security_state`、`resource_state`。普通节点只能看到本节点状态、直邻、已知坏链路及它实际收发/转发的事件，不能读取全局图或 simulator truth。

### Replay 与 session

`labels.attack_subtype` 明确定义 `IMMEDIATE_REPLAY`、`DELAYED_REPLAY`、`OLD_SESSION_REPLAY`；`CAPTURE_AND_REPLAY` 仅为兼容别名。正常乱序由 `NORMAL_OUT_OF_ORDER` disturbance 表达且不生成攻击 label。在线 `replay_check_result` 为 `PASS`、`DUPLICATE`、`STALE`、`STALE_TIMESTAMP`、`INVALID_TIMESTAMP`、`WRONG_SESSION` 或 `UNAVAILABLE`。处理顺序固定为应用 HMAC、时间戳新鲜度、session/key epoch、ReplayWindow。状态按 immediate sender、immediate receiver、源 sequence namespace、business session、key epoch 隔离。同一 hop/key epoch 可并发多个合法业务 session；key epoch 轮换或明确过期将旧 security context 标为 stale。Replay transmission 不会自行激活旧 session。

### 应用层 HMAC

`online_features.security_state` 可选字段 `application_hmac_result` 为 `PASS`、`FAIL`、`MISSING`、`UNKNOWN_DEVICE`、`NOT_APPLICABLE` 或 `UNAVAILABLE`，并可带非秘密 `application_hmac_failure_reason`。业务报文使用设备独立密钥计算 HMAC-SHA-256 并截取 16 bytes；规范输入为原始业务方向、claimed device ID、packet type、sequence、整数毫秒时间戳、canonical payload 字节长度及 canonical JSON payload。`SKG_CONTROL` 不使用这套业务 HMAC（`NOT_APPLICABLE`），继续由 Person-A 身份握手保护。原始 HMAC key 不得进入 run/event/label/API。

### Observer-local traffic statistics

统计只基于该 `observer_node_id` 的 `RX_SUCCESS`/`RX_FAILURE`，默认 rolling window 为 1.0 s，可由 `RunConfig.traffic_statistics_window_s` 配置；这不是 C 的 0.2 s LSTM 序列窗口。定义如下：

| Field | Definition |
|---|---|
| `packet.packet_size_bytes` | canonical JSON application payload 的 UTF-8 字节数；不含 crypto/link/PHY overhead |
| `packet.inter_arrival_s` | 同 observer、direction、packet type、claimed source、session、key epoch 流的相邻 RX 间隔；首次为 null |
| `traffic.packet_rate_pps` | 窗口内该 receiver 所有来源的本地到达包数 / window seconds；先于应用 HMAC gate 计数 |
| `traffic.byte_rate_Bps` | 窗口内本地 canonical serialized application bytes / window seconds |
| `traffic.duplicate_count` | 本地 sequence stream 在窗口内确认的重复数 |
| `traffic.sequence_gap_count` | observer-local stream 最近统计窗口内检测且尚未补齐的 gap 数；合法迟到会消除 gap，检测时间超窗后不再计数（`traffic.recent_window_sequence_gaps`） |
| `traffic.rx_queue_length` | 观测时本节点 RX queue 长度 |
| `traffic.forward_queue_length` | 观测时本节点 forward queue 长度 |
| `traffic.drop_count` | 本节点累计 queue/PHY drop 数 |
| `traffic.latency_ms` | 窗口内成功接收的平均端到端/逐跳可得延迟 |
| `traffic.throughput_mbps` | 窗口内成功接收字节 × 8 / window / 1e6 |

`reset()` 清空全部统计器；不同 observer 不共享 accumulator。

## 真值边界

`events.jsonl` 禁止出现 `is_attacked`、攻击 family/subtype、攻击者真实身份、actual transmitter、原始/修改值、攻击引擎精确干扰功率、攻击/防御成功以及未来日志。`labels.jsonl` 独立保存 AttackPlan 区间、攻击实体、FDI 修改前后值与物理 outcome。在线 RuleEngine、ModelAdapter、RL observation 和 GCS runtime API 均不持有 label store。

RL 的明文相关 online state 是本节点可知的 `plaintext_protection_risk`、`protected_sensitive_count`、`unprotected_sensitive_count` 与 availability，仅由本地 sensitive/encrypted 状态形成。攻击者是否实际监听、capture 是否成功、是否恢复明文仍是 offline truth，不进入 RL。

六类正常干扰 `NORMAL_LOW_SNR`、`NORMAL_PACKET_LOSS`、`NORMAL_TRAFFIC_BURST`、`NORMAL_OUT_OF_ORDER`、`NORMAL_STATE_CHANGE`、`NORMAL_CONGESTION` 只改变事件中的可观测量，永不写 attack label。

## `MODEL_RESULT`

结果含 `result_id`、observer、decision time、模型名/版本、status、prediction、scores/confidence/quality、建议动作、evidence event IDs、inference time、error code 与 optional bounded `error_summary`。外部 adapter 的 reset/observe/health 统一经过 exception/timeout boundary；timeout 由 `model_inference_timeout_ms` 控制且不改变 sim time。未接正式模型时 health 为 `UNAVAILABLE`，Null adapter 默认不为每条事件制造高频结果；若调用方显式请求错误结果，则必须使用：

```json
{"status":"UNAVAILABLE","predicted_label":null,"scores":null,"confidence":null,"error_code":"MODEL_NOT_CONFIGURED"}
```

不得把缺模型、异常或超时伪装成 `NORMAL`。模型 detection/fusion/defense 使用 correlation ID 形成唯一 SecurityReport，并遵循真实 Leader→GCS 断链缓存/恢复路径。

所有在线事件先写入 event store，再经统一 dispatcher 按 adapter subscription 分发。BiLSTM 可收 RX/PHY/AUTH/QUEUE/NODE/TOPOLOGY 等基础事件；Dueling Q 可收这些状态事件以及 BiLSTM/RFF 的 `MODEL_RESULT`；RFF 只收合适 RX/PHY-RF 事件。同一模型不接收自己的结果，Dueling-Q 结果不回送，避免递归与训练 feature 回填。

## RF/RFF 契约

接收/PHY 事件中的 `online_features.phy.rf_sample_ref` 只允许引用“当前 receiver 对当前 hop”在 `rf_manifest.jsonl` 中的 `sample_id`；没有真实 IQ 时为 null。Follower→Leader 的 RF sample 不会成为 GCS 对 Leader→GCS hop 的直接 RF observation；若 Leader 在业务报告中携带上游 RFF 结论，它属于 report/security semantic。

每条 manifest 结构上必须包含全部 18 个字段：

`sample_id`、`file_path`、`device_id`、`claimed_device_id`、`device_model`、`session_id`、`receiver_id`、`receiver_model`、`center_frequency_hz`、`sample_rate_hz`、`bandwidth_hz`、`sample_format`、`sample_count`、`snr_db`、`rssi_dbm`、`capture_start_utc`、`data_source`、`label_quality`。

其中 `claimed_device_id`、`snr_db`、`rssi_dbm`、`capture_start_utc` 可为 null，但字段不能缺失；其它必填项不可为 null。非空 UTC 必须为带时区 ISO-8601，采样数与频率参数必须为正，`file_path` 必须位于该 run 的 `rf_samples/` 下且文件存在。非空 `rf_sample_ref` 必须命中唯一 manifest item。当前没有真实 IQ，因此 manifest/ref 为空是合法状态，平台不生成 fake IQ。

## Offline evaluator 口径

- 正样本单位：一个 attack episode；在 `[impact_start_s, end_s + grace]` 内至少一个 family/subtype、observer/evidence 与 resolved target/link scope 均匹配的告警记 TP=1，否则 FN=1。
- 同 episode 后续正确告警只增加 `alarm_count`/`duplicate_alarm_count`，不增加 TP 或 FP。
- 负样本单位：固定 evaluation windows。对应 family 无攻击的窗口有 alarm 为 FP，无 alarm 为 TN；`FPR=FP/(FP+TN)`。
- response timestamps 分开保存 detection/action/report/service recovery；`report_delay = report_received_time - detection_time`。
- `action_executed` 与 `defense_effective` 独立。episode 保留全部 relevant attempts；action delay 使用第一条 relevant executed action，denied recommendation 不能覆盖后续执行。有效性由 target-scoped malicious impact 是否下降、合法服务是否恢复及合法流量损伤综合判断。
- `legitimate_service_damage` 是可用分量（relative throughput loss、relative latency increase、legitimate drop ratio）截断至 `[0,1]` 后的算术平均；无可用基线则为 null。
- service recovery 是攻击结束后首次同时满足 throughput ≥ baseline × 0.8 且 latency ≤ baseline × 1.25 的合法成功接收时刻；报告相对 `end_s` 的时间。
- `PASSIVE_CAPTURE` 不进入普通 threat-detection confusion matrix；单独报告 plaintext exposure、ciphertext protection、content recovery、sensitive exposure、protection effective 和合法服务可用性。
- defense policy 按 family 分发：Flooding 看 receiver 总体到达速率、非法 HMAC 报文拒绝和合法服务连续性；Spoofing/FDI 看应用 HMAC 拒绝且业务未执行；Replay 要求 HMAC 先通过、再由时间戳/session/滑动窗口拒绝；Eavesdropping 单独评价密文保护与明文暴露。当前攻击合同不包含 DOS/JAMMING。

## 校验

```powershell
python -m tools.validate_dataset <run-directory>
```

validator 不信任输入：按 frozen schema 递归校验 required/type/nullable/enum/range/pattern/nested reference，并校验 ID 唯一性、observer 时间单调性、run/message/evidence 引用、计划 ID/fingerprint、攻击区间、在线真值泄漏、RF 路径 containment 与 manifest 引用。普通坏数据（例如字符串时间或 RSSI）只产生 `valid=false`/errors，绝不使 validator 崩溃。
