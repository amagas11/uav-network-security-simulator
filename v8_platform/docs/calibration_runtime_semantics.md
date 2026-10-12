# Calibration Runtime Semantics

## 数据到运行闭环

```text
licensed/versioned CalibrationDataset
  -> BaselineCalibrationFitter
  -> CalibrationProfile
  -> PlatformRuntimeFactory
  -> PersistentPhyModel
  -> actual RX/PHY/traffic events
  -> RuntimeCalibrationValidator
  -> source-v-runtime comparison
```

`CalibrationDataset` 校验字段、单位、license/version/hash；缺失保持 null/availability。synthetic fixture 只证明软件算法，maturity 必须为 TEST/DEVELOPMENT。

## Target statistic 与 actuator

| Descriptive target | Runtime control | Runtime effect |
|---|---|---|
| `rssi_mean_dbm` | `rssi_bias_db` | 在 path-loss/shadowing/fading/natural attenuation 后平移 RSSI，不固定为常数 |
| `snr_mean_db` | `snr_bias_db` | 调整 effective noise relationship，保留 link variation 与 interference |
| `packet_loss_ratio` | `background_loss_probability` | 与 physical PER、normal loss 按独立失败概率组合 |
| `latency_median_ms/p95_ms` | `base_latency_ms/latency_jitter_ms` | 加入实际 packet latency；使用独立 deterministic RNG stream |
| `throughput_mean_mbps` | none | `DESCRIPTIVE_VALIDATION_TARGET`；runtime throughput 由 bandwidth/SINR/PER 推导，不强行钳制 |

新 fitter 同时写 descriptive targets 与明确 controls。旧 profile 若只有 target statistics，loader 使用已文档化的 canonical baseline 映射生成 controls；runs.jsonl 写出实际 `calibration_runtime_controls` 与 `calibration_parameter_semantics`，避免把描述量冒充执行参数。

Calibration overlay 不覆盖 generic PHY interference 或 normal low-SNR：干扰仍进入 SINR，normal attenuation 仍在 bias 前改变信号，背景 loss 与自然 loss 组合。当前攻击合同不提供 JAMMING；这里描述的是可复用信道能力。统计验收使用多个 deterministic seeds 和宽容差比较方向，绝不要求逐 packet 仿真实测相等。

最终批准真实数据、license/hash 与真实拟合报告仍是 external data dependency；loader/fitter/actuation/comparison/entrypoints 是 B 已完成软件责任。
