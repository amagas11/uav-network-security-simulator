# 射频指纹基础模块使用说明

## 当前范围

已完成实施计划的第一阶段：生成模拟射频指纹、建立接收端合法模板、逐跳识别物理发射源，并记录结果。默认启用 `rff_enabled=True`、`rff_policy_mode="OBSERVE_ONLY"`。

默认模式只观察。现有 HMAC、重放检查、业务检测、入队、丢包和业务执行仍按原有逻辑运行。2026-10-26 已加入第二阶段的 `ENFORCE` 准入防御、DoS 压力严格白名单、真实链路上报、无上层协议模式及独立物理评估，详见 [第二阶段说明](rff_enforcement_guide.md)。本篇主要介绍基础观测和默认观察模式。

## 数据从哪里来

采用特征级仿真，不生成 IQ 波形，也不将指纹写入业务报文。每台设备拥有由运行种子和设备 ID 确定的八维发射机基线：载波频偏、I/Q 增益和相位不平衡、I/Q 直流偏移、功放幅度和相位非线性、时钟偏差。

每次无线接收时，仿真器依据本次实际发射设备，在私有基线上加入按仿真时间变化的缓慢漂移、接收机固定偏差、信道残余影响和测量噪声，形成接收端的指纹观测。SINR 和 PHY 测量质量决定观测质量及噪声幅度。它们本身不进入设备身份向量。这里的“质量”也是模型生成的仿真量，不是从真实波形测得的指标。

实际发射者仅用于仿真观测生成，识别器只能读取带噪观测、声明的本跳地址和接收端模板。在线事件不会包含真实攻击源、攻击类型标签或无噪声设备基线。

## 正常通信流程

```text
当前发送设备
  -> 生成无线帧及声明的本跳发送方 ID
  -> 现有 PHY 计算接收观测与解码结果
  -> 生成接收端带噪 RFF 观测
  -> 使用当前接收端的合法邻居模板计算距离
  -> 比较识别设备与声明本跳发送方 ID
  -> 写入 RX_SUCCESS / RX_FAILURE
  -> 解码成功的帧按原有路径进入 HMAC、接收队列和业务处理
```

指纹观测放在接收端 `phy.rff_observation` 中，与本次收到的帧关联；它不作为业务载荷发送。排队处理时，每帧保存自身的识别结果，避免误用接收机随后收到的其他帧的结果。

以 `Follower 2 -> Leader 1 -> GCS 0` 为例：第一跳声明发送者为 2，接收指纹应对应设备 2；第二跳声明发送者为 1，指纹应对应设备 1。业务源 `claimed_src_id` 可以始终为 2，但不能用它代替本跳发送者做物理身份比较。

## 注册与识别

初始化时，只为合法直接邻居建立接收端本地模板，默认每台邻居采集 20 个模拟注册样本，保存均值和标准差。注册样本与正常接收采用一致的测量噪声统计条件，使用独立随机流，不影响后续通信或在线指纹样本。外部设备可以有私有模拟指纹，但不会自动进入合法模板库。

识别前检查观测是否存在、维度是否为八维、数值是否有效、质量是否合格。合格后，逐维按模板标准差归一化，再计算均方根距离。最近模板必须在距离阈值内，并与第二近模板保持足够间隔。置信度综合最近距离、候选间隔和观测质量。

| 结果 | 中文含义 |
| --- | --- |
| `MATCH` | 识别为合法设备，且与声明本跳身份一致 |
| `MISMATCH` | 识别为另一台合法设备，与声明本跳身份不一致 |
| `UNKNOWN` | 没有可接受的合法模板，或本跳声明身份缺失而无法确认匹配 |
| `AMBIGUOUS` | 多个候选模板过于接近，不能可靠区分 |
| `LOW_QUALITY` | 观测质量不足，不能可靠识别 |
| `UNAVAILABLE` | 缺少观测或输入不合法，并提供原因 |

外部攻击设备没有注册模板，通常输出 `UNKNOWN`。这与“识别出了攻击者的具体设备 ID”不同。仅凭身份异常也不能进一步断言它属于伪装、FDI 还是重放；这些攻击的分项评价需要实验结束后结合独立标签完成。

## 攻击与能力边界

| 场景 | 第一阶段的物理身份观测 |
| --- | --- |
| 外部复制后伪装发射 | 保存合法本跳地址，指纹来自外部设备，产生身份异常 |
| 外部截获、修改后发射 FDI | 包括额外复制注入和受控中继替换两条路径；保存合法本跳地址，观测外部设备指纹 |
| 外部重放捕获帧 | 保持原帧本跳声明，但本次指纹来自重放设备 |
| 外部 Flooding | 外部设备未注册，通常为 `UNKNOWN`；本阶段不执行 RFF 白名单丢弃 |
| 合法设备内部篡改业务内容 | 使用自身合法硬件时可以仍为 `MATCH`，需要上层检测 |
| 合法设备自己重发旧帧 | 物理身份可以仍匹配，需要序列号、时间戳等上层检查 |
| 被动窃听 | 没有新增异常发射，不生成 RFF 攻击告警 |

## 输入与输出字段

| 位置与字段 | 中文含义 |
| --- | --- |
| `online_features.packet.claimed_link_sender_id` | 接收端可读取的本跳声明发送方地址 |
| `online_features.phy.rff_observation.sample_id` | 本次接收观测的唯一编号 |
| `feature_schema` | 特征定义版本，目前为 `RFF_FEATURE_V1` |
| `feature_vector` | 八维带噪指纹观测；不可用时为空向量 |
| `quality` | 模拟观测质量，范围 0 到 1 |
| `extraction_status` / `missing_reason` | 模拟提取是否可用，以及缺失或低质量原因 |
| `online_features.security_state.rff_identity_result` | 当前身份识别结果 |
| `rff_predicted_device_id` | 模板识别出的合法设备；不确定时为空 |
| `rff_claimed_link_sender_id` | 本次用于比较的声明本跳身份 |
| `rff_distance` / `rff_threshold` | 最近模板的归一化距离与配置阈值 |
| `rff_identity_confidence` | 识别置信度，不等同于实测准确率 |
| `rff_quality` / `rff_reason` / `rff_last_update_s` | 观测质量、识别原因和仿真更新时间 |
| `run_record().rff_simulation` | 指纹模型来源、模式和阈值等运行记录 |

结果可以通过现有接收事件、节点状态快照及导出的 `events.jsonl` 读取。当前没有增加专用前端页面，也没有额外产生 RFF 告警上报报文。后续可以据这些字段对接展示。

显式传入外部 `rff` 模型适配器时，它替代默认模板识别器；模拟带噪观测继续生成。运行记录中的 `identification_provider` 会区分 `NEAREST_TEMPLATE` 与 `EXTERNAL_MODEL_ADAPTER`。原有模型接口继续可用。

## 配置与示例

常用配置为 `rff_enabled`、`rff_enrollment_samples`、`rff_quality_threshold`、`rff_distance_threshold` 和 `rff_min_identity_margin`。队列压力及严格模式相关字段现已用于第二阶段的准入判断，观察模式下不会执行防御。配置会参与新运行的语义校验值，旧数据集仍支持按其原有配置验证。

从 `v8_platform` 目录使用满足项目依赖的 Python 环境运行：

```python
from swarm_sim import PlatformRuntime, RunConfig

runtime = PlatformRuntime(RunConfig(
    duration_s=1.0,
    auto_traffic=False,
    rff_enabled=True,
    rff_policy_mode="OBSERVE_ONLY",
))
message_id = runtime.queue_message(2, 1, "TELEMETRY", {"altitude_m": 100.0})
runtime.run_to_completion()
for event in runtime.events:
    if event["event_type"] == "RX_SUCCESS" and event["message_id"] == message_id:
        print(event["online_features"]["phy"]["rff_observation"])
        print(event["online_features"]["security_state"])
```

核心代码为 `swarm_sim/rff.py`；接收挂接和攻击逐跳身份处理在 `swarm_sim/runtime.py`，字段格式在 `swarm_sim/events.py`、`swarm_sim/domain.py` 和 `dataset/schema.json`。两个加密实现均设置本跳声明身份。

## 验证范围

新增测试覆盖设备可复现性、时间漂移、独立噪声、注册一致性、各识别状态、正常直连和多跳、解码失败、延迟认证、外部攻击、被动窃听边界、关闭模块后的业务一致性、在线真值隔离、旧数据集和非法特征向量校验。

另外以种子 0 至 9 分别运行 10 秒无攻击场景，980 次接收观测均为 `MATCH`，距离均值约 1.175、最大值约 2.555，质量范围约 0.883 至 0.967。这仅是当前仿真参数的正常样本检查，不代表真实设备识别准确率，也不足以证明可以直接启用防御。第二阶段仍需扩大正常/攻击/低质量样本对比，再确定执行阈值。

2026-10-21 最终验收：干净代码副本全量 `pytest` 为 **662 passed**，附带一条第三方 Starlette 测试客户端弃用提示。主目录与验收副本的 12 个相关源码/测试文件已逐文件核对 SHA-256 一致。独立代码复核发现的延迟处理结果关联问题已修复，并通过复核回归。

验收副本包含仓库文件及本次新增源码、测试、说明；保留在主目录的个人资料不进入副本。主目录直接全量测试时，原有可移植打包测试会因额外的中文命名 Word 文档没有英文路径映射而失败；打包器和这些个人文档均未改动，干净副本中的该测试正常通过。
