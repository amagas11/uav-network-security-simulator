# 三类模型训练数据与平台接口需求 V1

## 1. 文档目的

本文面向人员B，用于一次性确定双向LSTM、Dueling Q-learning和射频指纹模型共同依赖的数据、日志、攻击标签、训练环境及模型接入方式。B按本文建设统一的数据底座，C在该底座上完成三类模型的训练、验证和导出。后续模型参数、网络结构或窗口长度的调整，不应再要求B修改底层日志和通信主流程。

本文只规定C训练模型所需的输入和B需要提供的平台能力，不把攻击引擎、信道、日志数据库、前后端或防御动作划给C。职责边界如下：

- B负责产生正常及攻击过程、记录节点实际观测、保存攻击真实情况、导出数据、提供强化学习环境并接入模型。
- C负责定义数据含义、检查数据质量、构造训练样本、训练三类模型、确定阈值并交付模型及测试报告。
- A通过B提供认证结果、密钥状态和密钥版本等非秘密状态；任何原始密钥不得进入模型数据。

## 2. 一次建设的数据底座

### 2.1 数据目录

B每次批量实验应生成一个独立目录，至少包含以下内容：

```text
dataset/
  schema.json
  runs.jsonl
  events.jsonl
  labels.jsonl
  rf_manifest.jsonl
  rf_samples/
```

各文件用途如下：

|文件|内容|是否可作为在线模型输入|
|-|-|-|
|`schema.json`|数据版本、字段解释、单位和枚举值|否，仅用于解释数据|
|`runs.jsonl`|每次仿真实验的配置、随机种子和数据来源|仅可使用部署时已知的配置|
|`events.jsonl`|各节点在运行过程中实际能够观察到的报文、信道、流量、节点和拓扑信息|是|
|`labels.jsonl`|攻击类型、攻击者、原始值、攻击时段和攻击结果等真实情况|否，只用于训练标签和离线评价|
|`rf_manifest.jsonl`|射频采样文件、设备标签和采集条件|标签字段仅用于训练和评价|
|`rf_samples/`|IQ采样或已批准的射频特征文件|根据模型配置使用|

结构化记录以UTF-8 JSONL作为V1必选格式，每行一个完整JSON对象。B可以同时导出Parquet提高训练效率，但Parquet内容必须与JSONL语义一致。IQ数据不写入JSONL正文，只在`rf_manifest.jsonl`中保存文件引用。

### 2.2 统一标识和时间

所有文件必须使用以下统一字段进行关联：

|字段|含义|要求|
|-|-|-|
|`schema_version`|数据结构版本|V1固定为`1.0.0`|
|`run_id`|一次完整仿真实验的唯一编号|不同运行不得重复|
|`event_id`|一次发送、接收、信道观测或节点状态变化的唯一编号|全数据集唯一|
|`message_id`|同一业务报文在发送、逐跳转发和接收过程中的关联编号|重放报文保留原`message_id`，产生新的`event_id`|
|`sim_time_s`|仿真时间，单位秒|模型排序和滑窗只使用该字段|
|`observer_node_id`|产生该条观测的节点|表示模型部署位置能够看到什么|
|`observer_role`|观测节点角色|枚举为`GCS`、`LEADER`、`FOLLOWER`、`EXTERNAL`|

不得使用`time.time()`产生的墙上时间作为模型主要时序。墙上时间可以另外记录为`wall_time_utc`，但不能替代可重复的`sim_time_s`。

每次实验必须保存随机种子。相同代码、配置、种子和数据版本应能够复现实验事件顺序和攻击计划。

### 2.3 运行记录

`runs.jsonl`每行描述一次完整实验。V1要求如下：

```json
{
  "schema_version": "1.0.0",
  "run_id": "run-000001",
  "seed": 42,
  "duration_s": 60.0,
  "node_count": 3,
  "node_roles": {
    "0": "GCS",
    "1": "LEADER",
    "2": "FOLLOWER"
  },
  "data_source": {
    "kind": "calibrated_simulation",
    "source_dataset_version": "uav-radio-v1",
    "calibration_version": "channel-calibration-v1"
  },
  "profiles": {
    "channel_profile_id": "channel-default-v1",
    "traffic_profile_id": "traffic-default-v1",
    "attack_plan_id": "fdi-medium-v1"
  },
  "software_version": "platform-v1"
}
```

`data_source.kind`允许以下取值：

- `simulation`：未使用实测校准的纯仿真数据。
- `calibrated_simulation`：使用真实数据拟合参数后生成的仿真数据。
- `real_measurement`：真实采集或公开数据集中的直接观测。
- `augmented_real`：对真实记录进行可追踪扩增得到的数据。

训练和测试报告必须区分这四类来源，不得混成一个无法解释的总准确率。

## 3. 运行事件数据

### 3.1 事件类型

`events.jsonl`用于保存各节点能够实际观察到的信息。B至少支持以下事件类型：

|`event_type`|产生条件|
|-|-|
|`TX`|节点发送报文|
|`RX_SUCCESS`|接收节点成功解码报文|
|`RX_FAILURE`|接收节点未成功解码，但能够得到物理层观测|
|`PHY_SAMPLE`|接收机周期性信道观测，即使当前没有成功报文|
|`QUEUE_SAMPLE`|接收或转发队列的周期状态|
|`NODE_STATE`|节点状态或传感器状态更新|
|`TOPOLOGY_UPDATE`|节点实际获知的邻居或链路状态变化|
|`AUTH_RESULT`|报文认证、会话或重放检查结果|
|`MODEL_RESULT`|已部署模型产生结果，仅用于部署评估，不得回填到原始训练特征|
|`DEFENSE_RESULT`|防御请求及实际执行结果，仅用于策略训练和评价|

DoS干扰可能导致报文完全无法解码，因此`RX_FAILURE`和`PHY_SAMPLE`必须独立于成功报文产生。不能只记录成功到达的报文，否则模型无法学习干扰期间发生了什么。

### 3.2 事件记录结构

每条事件采用统一外层结构，不适用的字段使用`null`，不删除字段或用0伪装缺失值：

```json
{
  "schema_version": "1.0.0",
  "run_id": "run-000001",
  "event_id": "evt-00001234",
  "message_id": "msg-00000456",
  "sim_time_s": 12.4,
  "event_type": "RX_SUCCESS",
  "observer_node_id": 1,
  "observer_role": "LEADER",
  "online_features": {
    "packet": {},
    "phy": {},
    "traffic": {},
    "node_state": {},
    "topology": {},
    "security_state": {},
    "resource_state": {}
  },
  "availability": {},
  "extensions": {}
}
```

`availability`记录字段是否真实可见，例如：

```json
{
  "payload_available": true,
  "phy_available": true,
  "sensor_available": false,
  "missing_reason": "SENSOR_NOT_IMPLEMENTED"
}
```

### 3.3 报文特征

`online_features.packet`至少包含：

|字段|类型|含义|
|-|-|-|
|`claimed_src_id`|整数或`null`|报文中声明的源节点|
|`claimed_dst_id`|整数或`null`|报文中声明的目的节点|
|`packet_type`|字符串或`null`|遥测、任务、心跳、告警、视频帧等业务类型|
|`packet_size_bytes`|整数或`null`|报文长度|
|`sequence_no`|整数或`null`|报文序列号|
|`session_id`|字符串或`null`|当前通信会话|
|`key_epoch`|字符串或整数或`null`|密钥版本，不含密钥值|
|`hop_index`|整数或`null`|当前是第几跳|
|`link_id`|字符串或整数或`null`|当前直接接收链路|
|`inter_arrival_s`|浮点数或`null`|该观察点同类报文到达间隔|
|`encrypted`|布尔值或`null`|线上内容是否加密|
|`payload_numeric`|对象或`null`|成功解密且有权限后可见的数值业务字段|
|`command_type`|字符串或`null`|成功解密且有权限后可见的命令类型|

`payload_numeric`保留结构化数值，不由B提前拼成文本。例如遥测可包含：

```json
{
  "battery_pct": 78.2,
  "position_x_m": 120.5,
  "position_y_m": 40.0,
  "altitude_m": 98.1,
  "velocity_x_mps": null,
  "velocity_y_mps": null,
  "velocity_z_mps": null,
  "roll_deg": null,
  "pitch_deg": null,
  "yaw_deg": null
}
```

当前尚未实现的速度、姿态或其他传感器字段先保留为`null`，以后补充数值时无需修改数据结构。

### 3.4 物理层和信道特征

`online_features.phy`至少包含：

|字段|单位|要求|
|-|-|-|
|`rssi_dbm`|dBm|接收机可观测接收功率|
|`snr_db`|dB|信噪比|
|`sinr_db`|dB|信干噪比|
|`noise_power_dbm`|dBm|噪声功率估计|
|`interference_power_dbm`|dBm|接收机可估计时填写，否则为`null`|
|`per_estimate`|0至1|当前误包率估计|
|`decode_success`|布尔值|是否成功解码|
|`channel_busy_ratio`|0至1或`null`|信道忙占用比例|
|`frequency_hz`|Hz|当前工作频率|
|`bandwidth_hz`|Hz|当前带宽|
|`channel_id`|字符串或整数|当前信道编号|
|`measurement_quality`|0至1|该次观测的质量|

攻击配置中的真实干扰功率、攻击开关和攻击类型不属于接收机观测，不能放进该对象。若仿真能够提供“接收机估计的干扰功率”，必须与攻击引擎设置的真实干扰功率使用不同字段。

### 3.5 流量、节点、拓扑和安全状态

`online_features.traffic`至少包含当前观察点在最近统计周期内可见的：

- `packet_rate_pps`：每秒报文数。
- `byte_rate_Bps`：每秒字节数。
- `duplicate_count`：重复序列号数量。
- `sequence_gap_count`：序列缺口数量。
- `rx_queue_length`：接收队列长度。
- `forward_queue_length`：转发队列长度。
- `drop_count`：该观察点已知的丢弃数。
- `latency_ms`：可计算时的时延。
- `throughput_mbps`：有效吞吐量。

`online_features.node_state`至少包含：

- `battery_pct`、`flight_state`、`network_slice`。
- `position_xyz_m`、`target_position_xyz_m`。
- 预留`velocity_xyz_mps`、`attitude_rpy_deg`和`sensor_quality`；当前没有时写`null`。
- 状态属于观察节点自身还是收到的对端遥测，使用`state_owner_node_id`明确区分。

`online_features.topology`只保存该观察节点在当前时刻实际获知的信息：

- `neighbor_ids`、`neighbor_link_ids`、`known_bad_link_ids`。
- `local_degree`、`leader_id`、`topology_version`。
- 不允许普通Follower直接读取仿真管理器中的全网真实拓扑。

`online_features.security_state`至少包含：

- `auth_result`：`PASS`、`FAIL`、`UNAVAILABLE`。
- `auth_failure_reason`：不包含秘密的失败原因。
- `replay_check_result`：`PASS`、`DUPLICATE`、`STALE`、`WRONG_SESSION`、`UNAVAILABLE`。
- `key_state`：`AVAILABLE`、`EXPIRED`、`MISSING`、`UPDATING`、`UNAVAILABLE`。
- `rff_identity_result`：射频指纹模型部署后填写，初期为`null`。

原始密钥、密码学中间值、可用于推导密钥的数据和未授权节点无法获得的全局状态不得写入训练日志。

`online_features.resource_state`预留CPU、内存、队列处理时间和模型推理时间。B当前无法提供时可以写`null`，但字段结构保持不变。

## 4. 攻击标签和答案隔离

### 4.1 标签记录

`labels.jsonl`只供训练、调参和离线评价使用，运行时检测器不得读取。每次攻击至少产生一条标签记录：

```json
{
  "schema_version": "1.0.0",
  "run_id": "run-000001",
  "label_id": "label-00031",
  "attack_family": "FDI",
  "attack_subtype": "TELEMETRY_GRADUAL_DRIFT",
  "scheduled_start_s": 10.0,
  "impact_start_s": 10.2,
  "end_s": 18.0,
  "attacker_node_id": 4,
  "target_node_ids": [1],
  "target_link_ids": [],
  "intensity": {
    "level": "MEDIUM",
    "value": 15.0,
    "unit": "m"
  },
  "truth": {
    "actual_transmitter_id": 4,
    "claimed_src_id": 4,
    "original_value": 100.0,
    "modified_value": 115.0
  },
  "outcome": {
    "attack_effective": true,
    "malicious_content_executed": false,
    "mission_impact": 0.2
  }
}
```

V1攻击类别和子类至少包括：

|攻击大类|必须覆盖的子类|
|-|-|
|`SPOOFING`|外部攻击者伪造合法节点、伪造未知节点、认证失败和身份冲突|
|`EAVESDROPPING`|敏感明文暴露、敏感密文保护、普通非敏感明文对照|
|`DOS`|`FLOODING`和`JAMMING`分别记录|
|`FDI`|命令替换、遥测突变、遥测缓慢漂移、越界值和逻辑矛盾|
|`REPLAY`|立即重放、延迟重放、旧会话重放和正常乱序对照|

正常运行不需要伪造一条攻击标签。训练样本在对应窗口内没有任何有效攻击标签时标记为`NORMAL`。

### 4.2 禁止泄漏到在线输入的字段

以下内容必须放在`labels.jsonl`或独立评价记录中，禁止进入`events.jsonl`的`online_features`：

```text
is_attacked
attack_type
attack_subtype
attacker_node_id
actual_src / actual_transmitter_id
original_command / original_value
is_dos_attack
attack_engine_jamming_power
attack_success
detection_triggered
detection_evidence
defense_action
defense_success
future_event_or_log
```

`event_id`和`run_id`可以同时出现在事件与标签文件中，用于C离线关联，但B不得在调用在线模型时把关联后的标签一同传入。

### 4.3 当前代码字段迁移规则

现有单帧返回对象可按下表迁移，避免B重新猜测字段用途：

|当前字段|V1去向|
|-|-|
|`packet.claimed_src`、`packet.claimed_dst`|`events.online_features.packet`|
|`packet.actual_src`、`packet.original_command`|`labels.truth`，不得进入在线输入|
|`packet.traffic`|`events.online_features.packet`和`traffic`|
|`channel`中接收机可观测字段|`events.online_features.phy`|
|`channel.is_dos_attack`、`dos_jamming_power`|`labels.jsonl`|
|`network_performance`|`events.online_features.traffic`和`resource_state`|
|`dst_node_state`|`events.online_features.node_state`|
|`security.is_attacked`、`attack_type`、`attack_detail`|`labels.jsonl`|
|`security.detection_triggered`、`defense_action`|部署后的`MODEL_RESULT`和`DEFENSE_RESULT`，不作为原始训练特征|

## 5. 双向LSTM数据要求

### 5.1 任务定义

双向LSTM根据某个接收节点最近一段时间内的报文、信道、流量、节点和拓扑观测，判断窗口结束时的威胁类型。V1先训练单攻击分类模型，输出以下类别：

```text
NORMAL
SPOOFING
DOS
FDI
REPLAY
PLAINTEXT_EXPOSURE
```

`PLAINTEXT_EXPOSURE`表示敏感数据在缺少加密保护时存在泄露风险，不表示模型发现了完全被动的窃听者。纯被动窃听者是否正在监听只能作为离线攻击真值，不能进入在线模型输入。

后续复合攻击采用多标签输出，但B无需修改底层事件结构，只需允许同一时段存在多条攻击标签。

### 5.2 时间窗

V1默认窗口参数为：

- 每个`observer_node_id`独立构造时间序列。
- 窗口长度2秒，滑动步长0.5秒。
- 按0.2秒划分时间步，每个窗口10个时间步。
- 同一时间步内的多条事件由C进行计数、均值、最大值、最小值和最近值聚合。
- 缺失时间步由C填充，并生成缺失掩码；B不得用0伪装缺失。
- B只导出原始事件，不在平台中硬编码窗口长度，避免C调参时要求B修改代码。

窗口标签根据窗口结束时的有效攻击确定。C同时计算`attack_overlap_ratio`：攻击在窗口内覆盖不足25%的样本标记为过渡窗口，保留用于响应时间评价，默认不进入第一版主要分类训练。

### 5.3 LSTM使用的特征

第一版优先使用以下接收端可见特征：

- 报文类型、长度、到达间隔、序列号增量、是否加密、认证及重放检查结果。
- RSSI、SNR、SINR、PER、解码成功率、信道忙占比。
- 报文速率、字节速率、重复数、序列缺口、队列长度、时延和吞吐量。
- 电量、位置、高度、飞行状态、目标位置，以及可用时的速度和姿态。
- 当前邻居数量、已知异常链路数量和拓扑版本变化。
- 字段可用性、传感器质量和物理层观测质量。

C负责类别编码、标准化、缺失掩码和窗口聚合。所有标准化参数只使用训练集拟合。

### 5.4 LSTM样本生成要求

B必须支持持续攻击，而不是仅修改单个报文：

- 攻击有明确开始、实际生效和结束时间。
- FDI在合法业务形成后、加密前注入，覆盖命令和连续遥测两种形式。
- Flooding产生真实报文到达、排队和合法业务退化。
- Jamming产生连续物理层观测，即使没有报文成功解码。
- Replay保留原报文标识，并生成新的接收事件。
- 正常数据包含自然低SNR、正常丢包、业务突发、合法乱序和合法状态变化。

建议数据规模：

|阶段|数据量|
|-|-|
|接口验证集|正常及每个类别至少10次独立运行，每次30至60秒|
|正式训练集|正常及每个类别至少50次独立运行，攻击至少包含低、中、高三档强度|
|最终测试集|使用从未参与训练和调参的完整运行，包含不同随机种子和参数组合|

窗口数量只作参考，不能用同一次运行切出的大量重叠窗口冒充大量独立样本。

### 5.5 LSTM数据划分

B提供完整运行，C在切窗前按`run_id`划分：

- 70%运行用于训练。
- 15%运行用于验证和阈值选择。
- 15%运行作为最终测试，不参与调参。

同一次运行、同一真实采集会话及其扩增版本必须位于同一数据子集。C在训练部分进行分组交叉验证，不允许随机打散相邻或重叠窗口后再划分。

## 6. Dueling Q-learning数据和环境要求

### 6.1 任务定义

Dueling Q-learning根据历史日志、当前网络状态、LSTM风险分数和资源状态，输出检测等级或防御策略建议。模型不直接修改节点、链路或黑名单；B根据权限、确定性规则和实际状态决定是否执行。

### 6.2 状态数据

状态由相同的`events.jsonl`构造，至少包括：

- 最近2秒及5秒的报文速率、错误率、队列、时延和吞吐量统计。
- 最近的RSSI、SNR、SINR、PER及其变化趋势。
- 认证失败、重放异常、明文暴露和射频身份异常的计数。
- LSTM各类别概率、置信度和数据质量；LSTM尚未部署时为`null`。
- 节点角色、电量、任务状态、邻居数量、异常链路和当前信道。
- 当前已启用的防御级别及资源开销。

攻击标签和未来日志只用于奖励计算，不能进入状态。

### 6.3 固定动作集合

为了避免后续改变平台动作接口，B按以下动作名称预留处理入口：

```text
NO_CHANGE
INCREASE_MONITORING
RECOMMEND_RATE_LIMIT
RECOMMEND_CHANNEL_SWITCH
RECOMMEND_DATA_ISOLATION
RECOMMEND_REAUTH_REKEY
```

这些都是建议动作。B返回动作是否被接受、是否实际执行、执行对象、执行时刻和失败原因。C不得绕过B直接修改仿真状态。

### 6.4 训练环境接口

B提供可重复的训练环境，语义上至少支持：

```text
reset(seed, run_config) -> initial_observation
step(action_request) -> next_observation, outcome, terminated
```

`reset`必须清空上一回合的队列、攻击状态、模型状态和统计值。`step`返回的`outcome`至少包含：

- 动作是否被允许及是否执行。
- 攻击是否造成实际影响。
- 是否阻止恶意报文或恢复合法业务。
- 是否误伤正常报文或正常节点。
- 从风险出现到动作执行的时间。
- 合法业务吞吐、时延和任务影响。
- 动作带来的通信和计算开销。

B只返回这些可解释的结果分量，不在平台中硬编码奖励权重。C根据实验目标组合正确检测、漏检、误报、响应时间、任务影响和资源开销形成奖励，因此后续调整奖励不需要B修改底层代码。

### 6.5 回合和数据量

- 每个回合使用独立`run_id`和随机种子。
- 回合包含正常阶段、攻击或扰动阶段、恢复阶段。
- 训练初期至少用100个回合验证环境和奖励方向，正式训练建议覆盖1000个以上回合及多种攻击强度。
- 训练、验证和最终测试使用不重叠的种子及攻击计划。
- 环境必须支持模型不可用、动作被拒绝、信道断开和上报失败等情况。

## 7. 射频指纹数据要求

### 7.1 任务定义

射频指纹模型根据发射机硬件造成的稳定信号差异，输出候选设备、置信度和未知设备状态，用于辅助身份认证和报文伪装检测。射频指纹正常只能说明“无线信号来自已登记设备”，不能证明报文业务内容真实，因此不能替代FDI行为检测。

### 7.2 IQ数据与清单

每条`rf_manifest.jsonl`至少包含：

|字段|含义|
|-|-|
|`sample_id`|射频样本唯一编号|
|`file_path`|相对于`rf_samples/`的IQ文件路径|
|`device_id`|真实物理发射设备编号，仅用于训练和评价|
|`claimed_device_id`|报文中声明的设备编号，可用于在线身份比对|
|`device_model`|设备型号|
|`session_id`|独立采集会话或日期编号|
|`receiver_id`|采集接收机编号|
|`receiver_model`|接收机型号|
|`center_frequency_hz`|中心频率|
|`sample_rate_hz`|采样率|
|`bandwidth_hz`|信号带宽|
|`sample_format`|例如`complex64`或双通道`float32`|
|`sample_count`|复采样点数量|
|`snr_db`、`rssi_dbm`|采集质量信息|
|`capture_start_utc`|采集批次时间，不作为身份特征|
|`data_source`|真实、公开、仿真或扩增来源|
|`label_quality`|标签可信等级和人工复核状态|

IQ文件推荐使用`.npy`或`.npz`保存复数数组；B保存原始连续采集和元数据，C负责切段、归一化、增强和特征提取。未经C确认，B不得只保留经过不可逆处理的少量特征而删除原始IQ。

### 7.3 数据覆盖和划分

可验证的射频指纹基线建议至少包含7台物理设备，其中5台作为已登记设备、2台作为未知设备：

- 5台以上已登记物理发射设备，其中尽量包含同型号设备。
- 每台已登记设备3次以上独立采集会话。
- 每台已登记设备每次会话至少100个可用片段，或等价长度的连续原始IQ。
- 另行保留至少2台完全不参与训练的设备用于未知设备测试。
- 覆盖不同SNR、接收距离或信道条件，避免模型只识别采集环境。

训练和测试必须按采集会话或整机设备分组。已登记设备跨会话识别和未知设备拒识分别报告，不能把两种任务混成一个准确率。

没有设备级IQ、射频特征或可信设备标签时，B仍需保留`rf_sample_ref`和模型接入位置，但C不能声明已经完成真实射频指纹训练。

## 8. 三种模型统一接入方式

### 8.1 C提供的适配器

B不需要了解每个模型内部的窗口、标准化或网络结构。C最终为每种模型提供统一适配器，语义如下：

```text
reset(run_info)
observe(event) -> zero_or_more_model_results
health() -> model_status
```

- `reset`在新实验开始时清空模型窗口和隐藏状态。
- `observe`接收一条符合V1的在线事件，由C的适配器自行完成窗口和预处理。
- 未形成完整窗口时可以不返回结果。
- `health`返回模型是否可用、版本和失败原因。

### 8.2 统一模型输出

三种模型统一返回以下外层结构：

```json
{
  "schema_version": "1.0.0",
  "run_id": "run-000001",
  "result_id": "result-00088",
  "observer_node_id": 1,
  "decision_time_s": 12.5,
  "model_name": "bilstm-threat-classifier",
  "model_version": "1.0.0",
  "status": "OK",
  "predicted_label": "FDI",
  "scores": {
    "NORMAL": 0.02,
    "SPOOFING": 0.01,
    "DOS": 0.03,
    "FDI": 0.91,
    "REPLAY": 0.02,
    "PLAINTEXT_EXPOSURE": 0.01
  },
  "confidence": 0.91,
  "quality": 0.88,
  "recommended_action": "RECOMMEND_DATA_ISOLATION",
  "evidence_event_ids": ["evt-00001230", "evt-00001234"],
  "inference_time_ms": 7.4,
  "error_code": null
}
```

射频指纹模型可在`scores`中使用设备编号和`UNKNOWN`，Dueling Q-learning可在`scores`中使用动作名称。模型失败时必须返回`status=ERROR`和明确`error_code`，B按规则降级，不能把失败默认为正常。

### 8.3 模型交付内容

C每个模型至少交付：

- 模型文件或权重。
- 训练代码和固定配置。
- 特征顺序、单位、类别编码和输入形状。
- 缺失值处理、标准化参数和窗口参数。
- 判断阈值及质量不足时的处理方式。
- 依赖版本、随机种子、数据版本和训练记录。
- 一组固定输入及其预期输出。
- 独立测试、误报漏报和失败案例报告。

B负责保存模型版本并调用适配器，不在前端使用攻击标签重新计算模型结论。

## 9. B需要一次性完成的平台改造

B按V1至少完成以下能力：

1. 建立统一仿真时钟、`run_id`、`event_id`、`message_id`和随机种子。
2. 将单帧返回改造成持续事件记录，支持JSONL导出和批量实验。
3. 把节点可见事件与攻击真实标签存入不同文件和不同运行接口。
4. 记录接收失败、无成功报文时的周期物理层观测和队列状态。
5. 支持具有开始、生效、持续和结束时间的攻击，而不是只攻击一帧。
6. 分开实现Flooding与Jamming，并提供自然拥塞、自然低SNR等正常对照。
7. 在加密前实现合法失陷节点FDI，并提供突变和渐变遥测样本。
8. 按观察节点记录局部邻居和链路变化，供C构造动态邻接信息。
9. 为Dueling Q-learning提供可重复的`reset/step`训练环境和动作执行结果。
10. 为射频指纹保留IQ/特征文件引用、采集元数据和运行时观测入口。
11. 在每个需要检测的节点提供统一模型适配器调用位置。
12. 模型不可用、数据缺失或推理超时时，使用现有确定性规则继续运行并记录降级状态。

## 10. C负责的数据处理和模型工作

C在B的数据底座完成后负责：

1. 提供V1数据校验程序，检查字段、类型、单位、唯一编号和标签引用。
2. 对缺失值、异常值、人工复核信息和数据来源进行处理并保留处理记录。
3. 在按运行或会话划分数据之后构造LSTM窗口，防止相邻窗口泄漏。
4. 训练统计基线、双向LSTM、Dueling Q-learning及所需射频指纹模型。
5. 进行分组交叉验证、独立测试、类别消融、规则与模型对照和失败案例分析。
6. 分别报告真实数据、校准仿真、纯仿真和扩增数据结果。
7. 导出统一模型适配器，并与B验证离线和平台推理结果一致。

## 11. 数据接口验收清单

在B批量生成正式训练数据前，C使用一小批样本逐项验收：

- [ ] `schema_version`、`run_id`、`event_id`和`sim_time_s`完整且格式正确。
- [ ] 相同种子和配置能够复现事件顺序及攻击计划。
- [ ] 发送、逐跳接收、接收失败和周期物理层观测可以关联。
- [ ] 攻击标签与在线事件物理分离，在线输入不含禁止字段。
- [ ] 每种攻击具有开始、生效和结束时间，并能定位目标节点或链路。
- [ ] 正常数据包含与攻击相似的自然波动和业务变化。
- [ ] 每个接收节点只能获得自己或已成功上报的信息。
- [ ] 缺失值使用`null`和可用性标记，不使用0代替未知值。
- [ ] 所有物理量单位固定，枚举值在`schema.json`中列明。
- [ ] LSTM能够按观察节点构造连续2秒窗口和缺失掩码。
- [ ] Dueling Q-learning环境可重置、推进，并返回实际动作结果。
- [ ] 射频样本可通过清单定位，设备、会话、接收机和采样参数齐全。
- [ ] 模型输出能够通过实际仿真链路记录和上报，前端不读取离线真值。

只有上述检查通过，C才开始正式训练。若某字段暂时无法获得，B应保留字段并写`null`及缺失原因；这不会阻止接口冻结，但C需要在模型报告中说明该特征未使用。

## 12. 版本和变更规则

V1采用`schema_version=1.0.0`，遵守以下兼容规则：

1. 已有字段不得删除、改名、改变类型或改变单位含义。
2. 新增非必填字段放在现有对象或`extensions`中，并提升次版本号，例如`1.1.0`。
3. 新增枚举值必须同步更新`schema.json`，旧读取程序对未知枚举按`UNKNOWN`处理。
4. 修正文档说明但不改变数据含义时提升修订号，例如`1.0.1`。
5. 改变必填字段、单位或事件语义属于不兼容变更，必须提升主版本号并保留迁移工具。
6. C调整窗口、模型层数、奖励权重、阈值或训练参数不属于平台数据结构变更。

本规范冻结的是公共数据和平台能力，不冻结模型内部实现。B完成V1后，C可以在不修改通信、攻击、日志和前端底层结构的情况下继续训练和替换三类模型。
