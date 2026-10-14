# 无人机仿真平台射频指纹第二层检测设计

## 1. 设计目标

平台现有第一层检测依赖应用层报文、HMAC、序列号、时间戳和业务状态。
本设计增加独立的第二层物理身份检测。当厂商不开放业务载荷和上层协议时，
接收端仍可使用本跳发送方ID或链路地址，以及本地测得的射频指纹判断无线
发射源身份。

第二层覆盖以下外部重新发射场景：

- 报文伪装：攻击者复制报文后伪造合法本跳地址并重新发射；
- FDI：攻击者截获、修改载荷并保留合法本跳地址后重新发射；
- Flooding DoS：队列或总到达速率进入压力状态后，对每个到达信号执行严格白名单过滤；
- 重放：攻击者使用自己的射频设备重新发送捕获的合法帧。

被动窃听没有新的异常无线发射，不纳入在线检测。合法设备自身被攻陷后使用
自身射频硬件发送恶意内容，也不能仅靠射频指纹识别，仍需第一层检测。

## 2. 输入边界

无上层协议模式下，第二层只允许使用：

- 接收端可获得的本跳发送方ID或链路地址；
- 当前接收端测得的射频指纹特征；
- 当前接收端测得的SINR、RSSI和测量质量；
- 接收端自己的合法设备模板和白名单；
- 接收端本地总到达速率和接收队列占用率；
- 仿真时钟和检测器自身历史状态。

第二层不得读取：

- `runtime_attack_id`、攻击类型或真实攻击源标签；
- 仿真器内部的`actual_transmitter_id`；
- 无噪声设备指纹基线；
- 未来事件、离线评价结果或攻击计划；
- 在无上层协议模式下不可获得的业务载荷、HMAC、序列号和时间戳。

真实攻击源和攻击类型只能写入离线标签，用于实验结束后的检测率评估。

## 3. 身份语义

### 3.1 三类身份

- `claimed_src_id`：端到端业务源身份，可能在多跳转发过程中保持不变；
- `claimed_link_sender_id`：无线帧声明的本跳发送身份，是第二层比较对象；
- `actual_transmitter_id`：真正发射无线信号的设备，只能由仿真信道内部使用。

### 3.2 多跳约束

在`Follower -> Leader -> GCS`链路中，GCS接收到的物理信号来自Leader，
即使业务源仍为Follower。因此接收端必须比较：

```text
predicted_transmitter_id == claimed_link_sender_id
```

不得直接比较`predicted_transmitter_id`和端到端`claimed_src_id`。正常中继每完成
一跳发送，都将`claimed_link_sender_id`更新为当前合法中继；复制、FDI和重放
攻击保留或伪造原合法本跳地址。

## 4. 实现方式选择

采用特征级射频指纹仿真，不把`rf_feature_vector`写入报文字段，也不生成虚假IQ文件。
每台设备具有固定发射机特征基线，接收端在每次无线接收时得到带漂移和噪声的
观测向量。该方式符合射频指纹由接收端测量的方向，同时适配当前离散报文和PHY模型。

完整IQ波形、调制解调和训练模型不在第一版范围内。现有外部RFF模型插槽继续保留，
未来可用真实数据训练的识别器替换确定性模板识别器，而不改变事件和防御接口。

## 5. 射频指纹模型

### 5.1 特征模式

第一版使用`RFF_FEATURE_V1`八维特征：

1. `cfo_ppm`：载波频率偏移；
2. `iq_gain_imbalance_db`：I/Q增益不平衡；
3. `iq_phase_imbalance_deg`：I/Q相位不平衡；
4. `dc_offset_i`：I路直流偏移；
5. `dc_offset_q`：Q路直流偏移；
6. `pa_am_am`：功放幅度非线性；
7. `pa_am_pm`：功放相位非线性；
8. `clock_skew_ppm`：设备时钟偏差。

这些值是特征级仿真量，不声称来自真实IQ提取。

### 5.2 设备基线

`DeviceRffProfileRegistry`根据运行种子和设备ID生成设备基线。相同种子、相同设备
必须可复现，不同设备应保持可区分。合法节点和外部攻击节点均有真实基线，但只有
合法节点可以进入接收端模板库。

### 5.3 接收观测

第`k`维观测定义为：

```text
x_k(t) = mu(device,k)
       + drift(device,k,t)
       + bias(receiver,k)
       + channel_residual(k,t)
       + measurement_noise(k,t)
```

- `mu`是设备固定基线；
- `drift`是设备随时间缓慢变化的AR(1)漂移；
- `bias`是接收机固定测量偏差；
- `channel_residual`是零均值信道残余影响；
- `measurement_noise`随SINR下降和测量质量降低而增大。

RSSI、CSI和SINR本身不作为设备身份特征，只用于调节观测噪声和质量，避免把
位置或信道状态错误地当成设备身份。

## 6. 模板注册与识别

### 6.1 接收端本地模板

每个合法接收节点维护独立的`ReceiverRffTemplateStore`。初始化阶段为每个允许
直接通信的合法邻居生成默认20个无攻击注册样本，并计算：

- 特征均值`feature_mean`；
- 特征标准差`feature_std`；
- 注册样本数；
- 特征模式版本；
- 接收节点ID和合法设备ID；
- 可配置距离阈值。

不同接收机的固定偏差不同，因此模板不能在接收端之间直接混用。动态合法节点
只有完成授权注册后才能加入相应接收端白名单。外部攻击节点永不自动注册。

### 6.2 质量门控

若RFF观测缺失或`quality`低于阈值，识别结果为`LOW_QUALITY`或`UNAVAILABLE`，
不能直接声称已识别攻击者。质量合格后才执行模板距离计算。

### 6.3 标准化距离

观测`x`与模板`j`的距离为：

```text
d_j = sqrt(sum(((x_k - mean_jk) / max(std_jk, sigma_floor_k))^2) / K)
```

选择距离最小的模板。如果最近距离小于阈值且与第二近模板有足够间隔，则输出该
设备ID；全部超过阈值时输出`UNKNOWN`；候选过于接近时输出`AMBIGUOUS`。
置信度由最近距离、候选间隔和观测质量共同计算。

## 7. 在线数据结构

### 7.1 帧字段

`Frame`新增：

```text
claimed_link_sender_id: int | None
```

该字段表示接收端能从本跳链路头获得的声明地址，不表示仿真真实发射者。

### 7.2 接收观测

`ReceivedFrame.phy`增加：

```json
{
  "rff_observation": {
    "sample_id": "rff-000001",
    "feature_schema": "RFF_FEATURE_V1",
    "feature_vector": [0.12, -0.08, 0.21, 0.03, -0.02, 0.17, -0.11, 0.06],
    "quality": 0.91,
    "extraction_status": "AVAILABLE",
    "missing_reason": null
  }
}
```

### 7.3 识别结果

`security_state`增加：

```json
{
  "rff_identity_result": "MATCH",
  "rff_predicted_device_id": 2,
  "rff_claimed_link_sender_id": 2,
  "rff_distance": 1.18,
  "rff_threshold": 3.0,
  "rff_confidence": 0.93,
  "rff_quality": 0.91,
  "rff_reason": "NEAREST_TEMPLATE_ACCEPTED"
}
```

允许的主要结果为`MATCH`、`MISMATCH`、`UNKNOWN`、`AMBIGUOUS`、`LOW_QUALITY`
和`UNAVAILABLE`。

## 8. 接收执行顺序

第二层插入现有`PHY -> RX_SUCCESS/RX_FAILURE -> ReceivedFrame -> RX queue`路径：

1. `_perform_air_transmission`使用实际`sender`调用PHY；
2. PHY生成RSSI、SINR、误包率等接收观测；
3. RFF生成器使用实际发射设备生成带噪指纹，但不输出真实设备ID；
4. 接收端记录总到达速率和队列压力；
5. 本地RFF识别器读取观测和模板；
6. 比较识别身份与`claimed_link_sender_id`；
7. 第一阶段只记录结果；第二阶段可在入队前执行丢弃；
8. 未被第二层拦截的帧继续进入现有HMAC、重放和业务检测路径；
9. 本地结果沿现有Leader/GCS报告链路汇总展示。

RFF观测可在载荷解码失败但仍检测到足够无线前导信号时存在，此时质量通常较低。
无法形成可靠特征时必须返回明确的不可用原因。

## 9. 四类攻击的检测与防御

### 9.1 报文伪装

攻击者实际发射，帧声明合法本跳身份。识别结果为攻击者或`UNKNOWN`，与声明身份
不一致，输出`RFF_IDENTITY_MISMATCH`并在执行模式下入队前丢弃。

### 9.2 FDI

本设计只覆盖外部攻击者截获、修改、保留合法地址并重新发射的FDI。物理识别身份
与声明身份不一致，执行相同的身份异常处理。合法设备内部在加密前修改业务内容时，
其RFF仍然合法，必须由第一层业务规则检测。

### 9.3 Flooding DoS

基础RFF识别始终可运行，以支持单帧攻击。接收总速率超过现有阈值，或接收队列
占用率超过配置阈值时，进入`RFF_STRICT_WHITELIST`模式。在该模式中，仅允许：

- 识别结果为合法白名单设备；
- 识别设备与本跳声明ID一致；
- 观测质量满足要求。

其他报文在入队前保护性丢弃。`LOW_QUALITY`只能记录为无法验证，不能统计为确定
识别到攻击者。压力恢复正常并持续配置时间后退出严格模式。本方案不引入令牌桶，
也不按业务类型设置优先级。

### 9.4 重放

外部攻击者重发完整捕获帧时，声明本跳身份仍为原合法设备，但射频指纹属于攻击者，
因此产生身份不匹配。若合法设备自身重放旧帧，RFF无法识别，需要第一层序列号、
时间戳和会话窗口检测。

### 9.5 在线标签边界

仅凭RFF不应在线声称异常一定属于伪装、FDI或重放。在线检测器只输出身份异常类型；
离线评估模块根据独立攻击标签，分别统计四类实验的检测率、误报率和响应时间。

## 10. 配置

第一版新增：

```text
rff_enabled = true
rff_policy_mode = OBSERVE_ONLY | ENFORCE
rff_enrollment_samples = 20
rff_quality_threshold = 0.45
rff_distance_threshold = 3.0
rff_min_identity_margin = 0.5
rff_queue_pressure_ratio = 0.60
rff_strict_hold_s = 2.0
rff_strict_on_rate_alarm = true
```

阈值是未校准仿真的初始配置，不得描述为真实无人机经验阈值。后续应通过正常样本和
攻击样本的仿真实验统计调整，并在运行记录中保存最终配置。

## 11. 代码边界

主要新增文件：

- `swarm_sim/rff.py`：RFF数据类、设备注册表、观测生成、模板库和识别器；
- `tests/test_rff_profiles.py`：基线、漂移、噪声和模板距离单元测试；
- `tests/integration/test_rff_receive_pipeline.py`：PHY到RX事件的集成测试；
- `tests/acceptance/test_rff_attack_detection.py`：四类攻击和能力边界验收测试。

主要修改文件：

- `swarm_sim/domain.py`：本跳声明身份和RFF接收状态；
- `swarm_sim/phy.py`：为特征生成提供接收质量，不泄漏真实身份；
- `swarm_sim/runtime.py`：初始化RFF服务并接入无线接收路径；
- `swarm_sim/events.py`：输出RFF观测和接收端识别结果；
- `swarm_sim/security.py`：第二阶段加入身份异常和严格白名单策略；
- `dataset/schema.json`：冻结新增在线字段和取值范围；
- 攻击注入代码：区分实际发射者和本跳声明地址。

## 12. 分阶段实施

### 第一阶段：基础框架

- 生成合法节点和外部节点的可复现设备基线；
- 建立接收端本地模板和白名单；
- 在PHY接收路径产生RFF观测；
- 输出识别结果和中心汇总；
- 使用`OBSERVE_ONLY`，不改变任何报文入队和业务结果。

### 第二阶段：检测与防御

- 身份不匹配的入队前丢弃；
- 队列压力触发严格白名单模式；
- 压力恢复和严格模式退出；
- 通过现有报告链路将告警和执行结果反馈至GCS；
- 分别计算四类攻击的检测与防御指标。

## 13. 验收标准

1. 相同种子下同一设备指纹可复现，不同设备基线可区分；
2. 正常直连报文识别为`MATCH`；
3. 正常多跳转发不把业务源和当前中继混淆；
4. 外部伪装、外部FDI和外部重放产生RFF身份不匹配；
5. Flooding压力触发严格白名单，攻击流量被拦截且合法设备仍可通过；
6. 压力解除后按配置退出严格模式；
7. 低质量样本不被错误统计为已识别攻击者；
8. 合法设备内部篡改和合法设备自身重放不会被虚假声称为RFF可检测；
9. 被动窃听不产生RFF攻击告警；
10. 在线事件不包含真实发射者、攻击标签或无噪声指纹；
11. 第一层关闭时第二层可独立运行；
12. 第二层关闭时现有第一层行为和测试结果保持不变。
