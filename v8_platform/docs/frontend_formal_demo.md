# V17 FINAL 正式演示前端

本前端是 V17 FINAL 五类攻击的正式演示入口，基于独立复制的 V16_FINAL。新增仿真时长控制和后端真实阶段累计；现有 report-derived 趋势、600 条明细与独立累计器、目标 DoS 证据和业务方向均保留。只读统计不参与检测、防御或 Evaluation 判定，不生成随机结果。V16_FINAL 保持只读原样。独立端口为前端 4178 / 后端 8107，详见根目录 START_V17.md。

未开始、INITIALIZED 或其他 family 的阶段为 0；评价 409 表示等待、其他评价失败显示暂不可用，不清除 COMPLETED run。评价失败重试间隔不少于 5 秒。DoS 认证失败报告与已执行 DROP 分开统计；GCS 本节点认证通过累计不再放入攻击主防御卡。Eaves 默认拓扑为隐藏 Eve 的合法通信配置视图；Replay 完整流程仅表示短路检测规则顺序。HMAC 卡区分协议、场景机制与在线验证。

## 页面与路由

| 路由 | 页面 | 当前机制 |
| --- | --- | --- |
| `/` | 系统总览 | 编队拓扑、运行指标、安全报告、真实趋势 |
| `/spoofing` | 报文伪装 | 仅修改声明源 ID，Application HMAC mismatch 后丢弃 |
| `/fdi` | FDI | `POST_HMAC_PRE_TRANSMISSION` 载荷修改，HMAC mismatch 后 `DROP / NO_UPDATE` |
| `/dos` | DoS/Flooding | 接收端总体到达速率检测，非法报文由 HMAC ingress gate 丢弃 |
| `/eavesdropping` | 窃听 | Person-A CSI/SKG 会话密钥与 AES-GCM 保密；直接检测为 N/A |
| `/replay` | 重放 | HMAC PASS 后依次执行时间戳、会话/epoch、序列滑动窗口检查 |

DoS 页面只支持 `FLOODING`，不展示或调度 JAMMING。C 侧模型训练与 readiness 属于历史规划，不纳入 V16 正式演示入口或验收范围。

## 数据来源边界

界面用标签明确区分三类数据：

- `Online Runtime`：来自 `GET /api/runtime` 的 GCS 可见事件、安全报告和网络指标。
- `场景配置 / 仿真真值`：来自创建请求、攻击计划与只读 `scenario_topology`；仅用于教学展示，不作为在线检测证据。
- `Offline Evaluation`：仅在运行完成后请求 `GET /api/evaluation`，不提前参与在线页面判定。

空值统一显示为 `—` 或 `N/A`；后端 0–1 比例统一转换为百分比。图表只累计真实 Runtime 数据，没有随机曲线和参考图示例数字。

## 状态与轮询

`src/stores/simulation.ts` 是唯一运行状态源。它维护 run 状态、metadata、拓扑、事件 cursor、安全报告、指标、历史点和离线评估。应用 Shell 只启动一个轮询计时器，路由切换不会重复创建 timer。事件按后端 cursor 增量追加；重置会清空累计历史。

五个攻击页的运行控制按 family 隔离：当前运行属于其他场景时，本页不能暂停或重置它；切换场景需要明确确认。总览页作为全局控制页保留暂停、继续与重置能力。子路由刷新后，DoS rate/duration 与 Replay subtype 会从当前 run metadata 恢复。

五攻击页面统一使用正式生命周期 API：

1. `POST /api/runs`
2. `POST /api/runs/start`
3. `POST /api/runs/pause` / `resume`
4. `POST /api/runs/reset`
5. `GET /api/runs/current`（空闲状态也返回 200，用于刷新恢复与服务连通性）
6. `GET /api/runs/status`
7. `GET /api/runtime`
8. 完成后 `GET /api/evaluation`

场景请求集中定义在 `src/config/scenarios.ts`，其中四类非窃听场景关闭 AES，窃听场景显式启用敏感数据加密并走正式 Person-A bundle。页面上的“检测机制已启用”“防御策略自动执行”是只读状态，不是假开关。

## 只读后端展示字段

为支持子路由刷新后恢复真实拓扑，`GET /api/runtime` 增加了可选的 `scenario_topology`。字段明确标记 `scope = SIMULATOR_SCENARIO_CONFIGURATION`，只包含节点角色/位置、物理链路及状态，不改变攻击、检测、防御、HMAC、Replay、Flooding 或 Person-A 语义。

V14 起，Leader 向 GCS 上报的 DOS summary 会保留目标接收端已生成的非秘密 evidence（detector node、observed rate、threshold、window、detection time 和 action result）；V16 继续沿用。该字段仅用于展示溯源，不改变 Flooding detector 或防御判定。DoS 页只以 attack target 对应的证据作为主告警，并将大量 HMAC 前置拒绝分区汇总。

`GET /api/runs/current` 只暴露可选的当前 `RunStatus`，用于把“后端可达但尚无 run”与“后端不可达”分开。业务 409/422/500 不会被误报为断线；健康探针失败两次后侧栏才显示连接异常。该端点不创建、推进或改变 Runtime。

## Legacy 前端边界

`Dashboard.vue`、`HomeView.vue`、`AttackControl.vue`、`Assessment.vue`、`Main.vue` 和 `Map.vue` 作为历史源码保留，不在 V16 正式 router / App import graph 中，也不属于正式演示入口。

## 验证

正式交付至少执行：

```text
npm run type-check
npm run build
python -m pytest -q
```

生产构建的六个子路由还应通过直接刷新 HTTP smoke；五个攻击配置应通过正式 FastAPI 创建、运行并完成相应 episode/eavesdropping protection evaluation。
