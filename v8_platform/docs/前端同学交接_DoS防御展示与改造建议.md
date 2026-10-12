# 前端同学交接：DoS 防御展示与改造建议

## 1. 文档目的

本文用于说明本轮后端已经完成的 DoS/Flooding 防御改造，以及前端需要同步调整的页面、接口类型和展示内容。

本轮后端只处理**应用层报文洪泛（DOS/FLOODING）**，没有修改其他四类攻击的检测逻辑，也没有修改现有 Vue 前端。前端改造的重点是把原来的“达到速率阈值后告警、非法报文由 HMAC 丢弃”，更新为现在已经落地的“告警、动态限流、恢复”完整过程。

---

## 2. 后端本轮已经完成的内容

### 2.1 原有逻辑

原平台的 DoS 页面主要展示两件事：

1. 接收节点统计单位时间内收到的所有报文，到达速率超过阈值后产生 Flooding 告警。
2. 外部攻击者发送的非法报文无法通过 Application HMAC 校验，因此在进入普通接收队列前被丢弃。

这套逻辑能够发现洪泛并过滤未认证报文，但“产生告警”本身不会降低后续报文处理压力；持有合法密钥的失陷节点也可能通过 HMAC 后继续高速发送。

### 2.2 新增的完整处理顺序

后端现在按照以下顺序处理成功解码的报文：

1. **统计接收端总体到达速率**：所有成功解码报文先进入速率统计，被限流的报文也会被计数。
2. **HMAC 前入口限流**：在执行解密和 HMAC 之前，先经过接收端全局桶和直接入口桶。
3. **加解密与 Application HMAC 校验**：入口允许后才进行原有安全校验。
4. **HMAC 后设备限流**：认证通过后，再按已认证的设备身份执行设备级限流。
5. **进入普通接收队列**：只有以上步骤全部通过的报文才进入后续业务处理。

这一区分很重要：HMAC 前不能相信报文中声明的源节点 ID，因此入口限流只使用接收端能够直接看到的发送节点和链路；只有 HMAC 通过后，才允许按认证设备身份限流。

### 2.3 三类令牌桶

| 限流范围 | 后端标识 | 作用 |
| --- | --- | --- |
| 接收端全局桶 | `receiver_global` | 限制某个接收节点进入认证流程的总体流量，防止多个入口共同洪泛。 |
| 直接入口桶 | `ingress` | 按直接发送节点和链路限制流量，防止单个入口持续占用资源。 |
| 认证设备桶 | `authenticated_device` | HMAC 通过后按真实认证设备限流，用于限制持有合法密钥但发送过快的失陷节点。 |

默认令牌补充速率为 `8 token/s`，桶容量为 `12 token`。短时间突发可以使用桶内已有令牌通过，持续高流量才会逐渐被限制。

### 2.4 DoS 防御状态机

每个接收节点分别维护防御状态：

| 状态 | 中文含义 | 默认进入条件 | 系统行为 |
| --- | --- | --- | --- |
| `NORMAL` | 正常 | 到达速率低于告警阈值 | 只统计，不启用新增限流。 |
| `ALERT` | 告警 | 到达速率达到告警阈值，默认 `8 pps` | 产生告警并提高监测等级。 |
| `LIMITING` | 限流中 | 达到严重阈值，或持续超过告警阈值 | 启用 HMAC 前和 HMAC 后令牌桶限流。 |
| `RECOVERING` | 恢复观察 | 速率下降到恢复阈值以下 | 暂停新增限流并观察流量是否稳定。 |

默认严重阈值为 `告警阈值 × 1.5`，即 `12 pps`；默认恢复阈值为 `告警阈值 × 0.7`，即 `5.6 pps`。速率连续低于恢复阈值 `2.0 s` 后回到 `NORMAL`。恢复期间如果速率再次升高，会重新进入 `LIMITING`。

状态恢复由仿真时钟驱动，即使没有新报文到达，也能从 `RECOVERING` 自动回到 `NORMAL`。

### 2.5 新增运行参数

创建仿真运行时，`POST /api/runs` 已支持以下参数：

| 字段 | 中文解释 | 默认值 | 约束 |
| --- | --- | ---: | --- |
| `flooding_detection_enabled` | 是否启用 Flooding 检测和自动限流 | `true` | 布尔值 |
| `flooding_packet_rate_threshold_pps` | 告警速率阈值 | `8.0` | 大于 0，单位 pps |
| `flooding_severe_rate_multiplier` | 严重阈值相对告警阈值的倍率 | `1.5` | 大于等于 1 |
| `flooding_sustained_overload_s` | 持续超限多久后进入限流 | `0.5` | 大于 0，单位秒 |
| `flooding_recovery_rate_multiplier` | 恢复阈值相对告警阈值的倍率 | `0.7` | 大于 0 且小于 1 |
| `flooding_recovery_hold_s` | 低流量保持多久后恢复正常 | `2.0` | 大于 0，单位秒 |
| `flooding_token_refill_rate_pps` | 令牌补充速率 | `8.0` | 大于 0，单位 token/s |
| `flooding_token_bucket_capacity` | 令牌桶容量 | `12.0` | 大于 0，单位 token |

前端当前的 `CreateRunRequest` 类型只有前两个字段，需要补上其余六个字段。前端不填写时，后端会使用默认值。

### 2.6 已完成的验证

后端完整测试已经通过 `666` 项测试。测试覆盖：

- 正常低速流量不告警、不限流；
- 短时突发在令牌容量内正常通过；
- 未认证攻击流量触发 HMAC 前限流；
- 认证设备持续洪泛触发 HMAC 后限流；
- 多入口洪泛由接收端全局桶限制；
- 攻击停止后自动恢复；
- 其他四类攻击的原有逻辑不受影响。

---

## 3. 前端当前与后端不一致的地方

当前 `DosView.vue` 仍然将 DoS 防护概括为：

1. 总体速率告警；
2. Application HMAC 前置过滤。

页面尚未展示以下已经实现的后端能力：

- `NORMAL → ALERT → LIMITING → RECOVERING → NORMAL` 状态变化；
- HMAC 前入口限流；
- HMAC 后认证设备限流；
- 全局桶、入口桶和认证设备桶的限流范围；
- 前置限流数量、后置限流数量和 HMAC 拒绝数量的区别；
- 攻击结束后的恢复时间和最终恢复状态；
- 新增的六个 DoS 防御配置参数。

因此，现有页面不能完整说明“系统已经真正降低洪泛流量处理压力”，容易让使用者仍然认为后端只有告警和 HMAC 丢弃。

---

## 4. 前端必须完成的改造

### 4.1 补充 API 类型与接口

建议修改 `src/api/index.ts`。

#### 4.1.1 补充创建运行参数

在 `CreateRunRequest` 中增加：

```ts
flooding_severe_rate_multiplier?: number
flooding_sustained_overload_s?: number
flooding_recovery_rate_multiplier?: number
flooding_recovery_hold_s?: number
flooding_token_refill_rate_pps?: number
flooding_token_bucket_capacity?: number
```

#### 4.1.2 增加节点观测接口

后端已有：

```http
GET /api/observations/{node_id}
```

建议前端增加：

```ts
export const getNodeObservation = (nodeId: number) =>
  get<NodeObservation>(`/observations/${encodeURIComponent(nodeId)}`)
```

最低限度的类型可以定义为：

```ts
export interface FloodDefenseResource {
  dos_defense_state: 'NORMAL' | 'ALERT' | 'LIMITING' | 'RECOVERING'
  packet_rate_pps: number
  alert_threshold_pps: number
  severe_threshold_pps: number
  recovery_threshold_pps: number
  rate_limit_active: boolean
  global_bucket_tokens: number | null
  pre_auth_limited_count: number
  post_auth_limited_count: number
  hmac_rejected_count: number
  limiting_started_at_s: number | null
  recovered_at_s: number | null
}

export interface NodeObservation {
  run_id: string
  observer_node_id: number
  sim_time_s: number
  defense_resource: FloodDefenseResource
}
```

### 4.2 在状态仓库中保存目标节点观测

建议修改 `src/stores/simulation.ts`：

- 增加 `targetNodeObservation` 状态；
- 当前运行是 DOS 场景并且已经取得目标节点 ID 时，调用节点观测接口；
- 与现有约 `700 ms` 的 Runtime 轮询同步刷新，不需要额外建立第二个定时器；
- 新运行、重置运行或切换场景时清空旧观测；
- 必须检查 `run_id`，避免上一轮运行的数据显示到当前页面；
- 节点观测接口暂时失败时保留页面基本运行信息，并把防御状态显示为“数据暂不可用”，不要把它显示成 `NORMAL`。

### 4.3 更新 DoS 页面顶部说明

建议把原来的说明：

```text
检测机制：Receiver Total Arrival Rate
过滤机制：Application HMAC Gate
```

更新为更完整、易懂的表述：

```text
检测机制：接收端总体到达速率与持续超限判断
防御机制：认证前入口限流 + HMAC 校验 + 认证后设备限流
```

不要把令牌桶写成“永久拉黑”或“隔离节点”。当前 DoS 限流是接收节点本地的临时防护，攻击结束后会自动恢复，也不会把来源加入永久 `rate_limited_peer_ids`。

### 4.4 增加防御状态面板

建议在现有“攻击目标接收端的 Flooding 检测”区域增加状态面板，至少显示：

- 当前状态；
- 当前接收速率；
- 是否正在限流；
- 开始限流时间；
- 最近恢复时间。

建议颜色：

| 状态 | 建议颜色 | 页面文字 |
| --- | --- | --- |
| `NORMAL` | 绿色 | 正常 |
| `ALERT` | 黄色 | 流量告警 |
| `LIMITING` | 红色 | 正在限流 |
| `RECOVERING` | 蓝色 | 恢复观察 |
| 数据缺失 | 灰色 | 数据暂不可用 |

状态颜色只用于辅助识别，页面上必须同时显示中文状态文字。

### 4.5 完善速率趋势图

现有趋势图只有“目标接收窗口速率”和“检测阈值”。建议增加：

- 当前接收速率；
- 告警阈值；
- 严重阈值；
- 恢复阈值。

阈值应使用节点观测接口返回的实际值，不要在前端重复计算。这样当后端参数改变时，页面仍然与实际运行一致。

现有 `receiver_rate_observations` 历史样本中只有告警阈值，严重阈值和恢复阈值目前是当前值。前端第一版可以在整张图上绘制当前运行的水平阈值线；不要伪造不存在的历史阈值变化。

### 4.6 增加拦截结果统计

建议增加一组并列统计，分别显示：

| 字段 | 中文名称 | 说明 |
| --- | --- | --- |
| `pre_auth_limited_count` | 认证前限流数量 | 报文在解密和 HMAC 前被入口令牌桶拒绝。 |
| `post_auth_limited_count` | 认证后限流数量 | 报文通过认证后，因认证设备发送过快被拒绝。 |
| `hmac_rejected_count` | HMAC 拒绝数量 | 已进入认证流程，但 Application HMAC 校验失败。 |

这三个数字不能合并成一个“拦截数量”，否则无法说明系统节省了哪一阶段的处理资源。

### 4.7 更新“防护链”说明

现有“两条真实防护链”建议改为“分层防御过程”：

1. **接收速率监测**：所有成功解码报文都参与统计。
2. **认证前入口限流**：限制接收端总流量和直接入口流量。
3. **加解密与 HMAC 校验**：拒绝无法认证或被篡改的报文。
4. **认证后设备限流**：限制持有合法凭据但发送过快的设备。
5. **自动恢复**：流量稳定下降后解除临时限流。

建议使用简单的横向步骤条或纵向步骤列表，不需要制作复杂动画。

### 4.8 增加状态变化和限流事件列表

现有 `/api/runtime` 已经提供增量事件。前端可以直接筛选以下事件：

#### 状态变化事件

```text
event_type = NODE_STATE
extensions.flood_defense_transition 存在
```

字段包括：

| 字段 | 中文解释 |
| --- | --- |
| `from_state` | 变化前状态 |
| `to_state` | 变化后状态 |
| `packet_rate_pps` | 发生变化时的接收速率 |
| `rate_limit_active` | 变化后是否处于限流状态 |

#### 限流丢弃事件

```text
event_type = DEFENSE_RESULT
extensions.rate_limit_admission 存在
```

字段包括：

| 字段 | 中文解释 |
| --- | --- |
| `stage` | `PRE_AUTH_RATE_LIMIT` 或 `POST_AUTH_RATE_LIMIT` |
| `allowed` | 当前为 `false`，表示报文被拒绝 |
| `reason` | 限流原因 |
| `bucket_scope` | 触发限流的桶范围 |
| `tokens_remaining` | 拒绝时剩余令牌数 |
| `evidence_event_id` | 对应的接收证据事件 ID |

页面可以将这两类事件合并成一张“DoS 防御过程”时间线，按仿真时间排序展示。

---

## 5. 建议增加的前端模块

以下模块不影响基本联调，但能明显提升平台的解释能力。

### 5.1 DoS 防御总览模块

建议在 DoS 页面靠前位置集中显示：

- 当前防御状态；
- 当前速率与三个阈值；
- 是否正在限流；
- 三类累计处理结果；
- 是否已经恢复。

该模块用于回答“现在有没有攻击、系统是否开始限制、限制发生在哪一层、最后是否恢复”四个核心问题。

### 5.2 令牌桶资源模块

后端当前节点观测接口只直接提供：

- `global_bucket_tokens`：接收端全局桶当前令牌数；
- 限流事件中的 `bucket_scope` 和当次 `tokens_remaining`。

因此第一版前端可以展示全局桶当前余额，并通过事件列表展示入口桶或认证设备桶触发情况。

**不要在当前接口基础上绘制三个实时令牌余额仪表盘。** 如果后续确实需要三个桶的完整实时余额，需要后端扩展观测接口，提供入口桶列表和认证设备桶列表后再开发。

### 5.3 状态时间线模块

使用 `flood_defense_transition` 事件展示：

```text
NORMAL → ALERT → LIMITING → RECOVERING → NORMAL
```

每个节点显示发生时间、当时速率和状态中文解释。没有发生的状态不要预先标记为已经完成。

### 5.4 高级参数模块

在“下一次启动参数”区域增加可折叠的“高级防御参数”，包含六个新增配置字段。普通演示可以继续使用默认值，实验人员展开后才能修改。

建议提供恢复默认值按钮，并在前端执行与后端一致的输入校验。后端返回 `422` 时，应显示具体字段错误，不要只提示“启动失败”。

### 5.5 在线数据与离线评价分区

页面继续保留现有来源标识：

- **在线 Runtime**：当前状态、速率、限流次数和事件；
- **离线评价**：仿真结束后的攻击阻断效果和合法业务影响。

不要用离线攻击标签驱动在线状态灯。在线页面只能显示后端在线观测和检测结果。

---

## 6. 推荐页面结构

建议保持现有 DoS 页面框架，按以下顺序调整：

1. 页面标题和机制说明；
2. 启动参数，新增可折叠的高级防御参数；
3. 场景拓扑；
4. 当前防御状态总览；
5. 接收速率与三条阈值线；
6. 分层防御过程；
7. 认证前限流、HMAC 拒绝、认证后限流统计；
8. 状态变化与限流事件时间线；
9. 仿真结束后的离线评价。

页面无需增加新的一级导航，所有内容放在现有 DoS 页面中即可。

---

## 7. 建议修改的前端文件

| 文件 | 建议修改内容 |
| --- | --- |
| `src/api/index.ts` | 补充六个运行参数、节点观测类型和 `getNodeObservation`。 |
| `src/stores/simulation.ts` | 保存并轮询目标节点观测，运行切换时清理旧数据。 |
| `src/views/attacks/DosView.vue` | 更新机制说明，增加状态、阈值、计数和恢复展示。 |
| `src/utils/dosPresentation.ts` | 增加状态中文映射、状态颜色、限流阶段和桶范围的中文映射。 |
| `src/components/common/` | 可选：增加复用的防御状态面板或防御时间线组件。 |

建议先在 `DosView.vue` 内完成最小版本，确认数据正确后再抽取公共组件，避免为单一页面提前建立复杂组件体系。

---

## 8. 空值与兼容规则

1. 新字段缺失或为 `null` 时显示 `—` 或“数据暂不可用”，不能显示为 `0`。
2. `rate_limit_active=false` 表示当前未限流，不代表本轮从未发生过限流。
3. `limiting_started_at_s` 和 `recovered_at_s` 是仿真时间，单位为秒。
4. 三个累计数量是当前节点、当前运行内的累计值，新运行开始后应清零。
5. 节点观测的 `run_id` 与当前运行不一致时必须丢弃。
6. `flooding_detection_enabled=false` 时仍可能存在基础到达统计，但不应显示 Flooding 告警或自动令牌桶限流。
7. 老数据没有新增字段时，页面应正常降级，不能导致整个 DoS 页面报错。

---

## 9. 建议实施顺序

1. 补充 TypeScript 类型和节点观测 API。
2. 在 Store 中接入目标节点观测并处理运行隔离。
3. 先显示当前状态、三类计数和恢复时间，完成最小联调。
4. 更新速率图，增加严重阈值和恢复阈值。
5. 筛选 Runtime 事件，增加状态时间线和限流事件表。
6. 最后增加高级参数输入和页面细节优化。

---

## 10. 前端验收标准

前端完成后至少验证以下场景：

1. 正常流量下状态为 `NORMAL`，三个处理计数为 0。
2. 流量达到告警阈值时显示 `ALERT`，页面不误写成已经限流。
3. 持续或严重洪泛时显示 `LIMITING`，并能看到认证前或认证后限流数量增加。
4. HMAC 拒绝和令牌桶限流分别统计，不重复解释为同一种处置。
5. 攻击结束后先显示 `RECOVERING`，最终回到 `NORMAL`。
6. 页面刷新后能够从当前运行恢复目标节点状态。
7. 重置或启动新运行后，不保留上一轮状态、计数和时间线。
8. 节点观测接口短暂失败时页面不崩溃，也不把缺失数据显示成正常状态。
9. 六个新增参数能够随创建运行请求传给后端，非法输入能够给出明确提示。
10. Spoofing、FDI、Replay 和 Eavesdropping 页面行为保持不变。

---

## 11. 本次交接结论

后端已经从“只告警、主要依赖 HMAC 丢弃”升级为“接收速率检测、认证前限流、安全认证、认证后限流、自动恢复”的完整 DoS 防御链路。前端不需要重新设计 DoS 攻击场景，主要工作是接入已有节点观测接口，把状态、限流层次、统计数量和恢复过程完整展示出来。

第一版应优先保证数据来源和含义正确，再进行样式优化。当前接口足以完成状态、阈值、全局桶余额、三类计数和事件时间线；入口桶及认证设备桶的完整实时余额暂未作为节点观测字段提供，不应由前端自行推测。
