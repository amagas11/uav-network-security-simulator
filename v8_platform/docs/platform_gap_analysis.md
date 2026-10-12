# 平台差距分析 V1

审计日期：2026-09-07。依据为根目录三份正式需求文档及 issue 工程实施规范。根目录代码与 `无人机/` 镜像源码逐文件 SHA-256 相同；本次以根目录为规范实现位置，镜像视为历史快照。

## 基线结论

现有工程是可运行的单包演示原型，不是需求所定义的可复现、逐跳、局部观测安全仿真平台。可复用资产包括业务到达分布、FSPL/阴影/Rician 静态模型、吞吐/时延计算、五类攻击入口、FastAPI 与 Vue 可视化骨架。

## 28 项指定审计结果

| # | 审计项 | 证据 | 结论 |
|---:|---|---|---|
| 1 | `SimulationManager.step()` 一帧一个 packet | 每次只调用一次 `next_packet` | 确认 |
| 2 | `time.sleep` 推进仿真 | `step()` 按到达间隔 sleep | 确认 |
| 3 | Replay/Eavesdropping 使用 `time.time` | 两攻击的监听超时和 detector stale 判断均使用墙钟 | 确认 |
| 4 | 业务任意 src/dst | `UavTrafficModel._endpoints()` 随机互发 | 确认 |
| 5 | GCS/Leader/Follower 真正角色 | `UAVNode` 无角色字段/权限 | 不存在 |
| 6 | topology 算 path、channel 直接发最终 dst | `NRChannel.transmit()` 取 path 后直接 `dst_node.secure_receive` | 确认 |
| 7 | 中间节点 RX/queue/forward/TX | 无中继处理 | 不存在 |
| 8 | NRChannel 每包重建 | `step()` 内实例化 | 确认 |
| 9 | persistent link state | 只有 topology 的布尔状态/干扰标量 | 不存在 |
| 10 | FDI 在 encryption 之后 | `src_node.encrypt_packet` 早于 attacker.execute | 确认，语义错误 |
| 11 | DoS 只做 Jamming | 唯一 DoS 类将 data 改为 `NOISE_JAMMING` | 确认 |
| 12 | Jamming 直接 report_bad_link | channel 注入分支直接调用 | 确认，越过检测/授权 |
| 13 | Flooding 真实 packet/queue pressure | 无 Flooding 子类/队列 | 不存在 |
| 14 | Eavesdropping 全局获得报文 | manager 对每个监听器调用 `sniff(packet)`，无位置/链路 | 确认 |
| 15 | Replay 状态隔离 | detector 只有全局 `seen_seqs` deque | 不满足 |
| 16 | Base64 错标 AES | Base64+salt 的 data 标为 `AES-256-GCM` | 确认，必须修复 |
| 17 | attack truth/online 混合 | 单步响应同时含 actual_src、original_command、attack_type 等 | 确认 |
| 18 | Detector 读取 attack truth | detector 当前未直接收 attack_type，但 channel metadata 带 truth 同义字段且边界未强制 | 存在泄漏风险 |
| 19 | GCS 读取全局状态 | 前端/API 直接返回 manager 全局拓扑/目标节点状态 | 确认 |
| 20 | 前端刷新调用 `/api/step` | `AttackControl.startPolling()` 每秒 `runStep()` | 确认 |
| 21 | Vue TypeScript 构建 | 当前机器缺少 `npm`，未取得有效 type-check/build 结果 | 环境阻塞待解决 |
| 22 | HomeView/router/types | router 引用不存在的 `views/HomeView.vue`，但 router 当前注释未挂载；大量 JS 无类型契约 | 确认 |
| 23 | `.git` 有效 | `master` 上有基线提交 | 有效但仓库卫生差 |
| 24 | Python tests 覆盖 | 仅 6 个 unittest，覆盖 traffic/PHY 两小块 | 严重不足 |
| 25 | 真实数据 | 未发现 manifest 或可核验数据 | 不存在/外部依赖 |
| 26 | 训练模型 | 未发现权重、训练流水线、ModelBundle | 不存在/外部依赖 C |
| 27 | 真实 RFF IQ | 未发现 IQ 与 manifest | 不存在/外部依赖 |
| 28 | 真实 calibration profile | 只有硬编码 simulation baseline | 不存在/外部依赖数据 |

## 工程卫生

- Git 基线追踪 22,048 个文件，其中 21,764 个为两份前端 `node_modules`，110 个为缓存/pyc；`.gitignore` 为空。
- 根目录与 `无人机/` 是重复源码树。为避免双重演化，根目录作为规范入口；历史镜像不在运行时导入。
- Python 依赖文件缺失；MATLAB import 已有 fallback，但 manager 构造时会尝试启动 MATLAB，副作用过大。
- baseline：Python 3.13.1 下 6/6 unittest 通过；`npm` 不在 PATH，因此前端 baseline 无法执行。

## 优先级

1. 冻结 schema、时钟、ID、RNG 与真值边界。
2. 建立角色化逐跳消息与持久链路，再把攻击/防御接在正确阶段。
3. 建立事件/标签/数据集、报告缓存、适配器和 evaluator。
4. 兼容旧 API；将 UI 改为只读轮询并显式分开 Runtime 与 Offline Evaluation。
5. 真实 SKG、C 模型、真实 IQ 与真实校准数据保持外部依赖，不制造结果。

## 最终关闭情况

上述 1–20、22、24 项的运行时缺口已由 `swarm_sim/`、兼容 facade、REST 生命周期和新 Dashboard 关闭；第 21 项随后使用官方便携 Node 22.14.0 完成了 `vue-tsc` 与 Vite production build。第 23 项已补齐 ignore/依赖，但历史已跟踪生成物未擅自删除，因此作为仓库卫生余项保留。第 25–28 项不是可由平台 B 伪造的内容，已分别落为 manifest/profile/adapter 接口与 `BLOCKED_EXTERNAL` 状态。最终状态以需求追踪矩阵为准。
