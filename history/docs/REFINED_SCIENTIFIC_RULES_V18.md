# V18 REFINED 运行证据补充

当前版本启动说明以 START_V18_REFINED.md 为准；旧 V17/V18 文档和旧 SHA 清单为历史基线，不作为 REFINED 文件校验。

FDI 原业务采用实际 node.position_xyz_m[2] 与 node.flight_state。altitude_m 是有界传感器测量：真实高度 + 0.04 sin(2π t/2 + 2π(seed mod 97)/97)，六位小数。未制造运动或消耗随机数。修改 k 序号的偏差为 0.1+0.04 sin(2π k/11)，只在 HMAC 后、发送前生效；真实修改记录与在线报告通过 event/message ID 关联。

目标 DoS 窗口观测成功解码到达、HMAC 前全部报文。窗口沿用既有 detector 的包含 cutoff 端点规则，不更改 detector；1 s 可能包含六批 0.2 s 调度突发。峰值不是配置平均速率，也不是首次告警 8 pps。只读采样不产生上报报文，每节点 320 点；峰值保存全 run 最大值。来源明确为目标接收端 Runtime 观测，不冒充 GCS 接收数据。

Eaves 捕获按 sensitive×encrypted 四类互斥分类，协议控制明文是实际 SKG_CONTROL 类型子集。Replay/Spoofing capture 标为真值完成记录，未完成时只能展示配置监听关系。新增证据不参与 detector/defense。

自定义仿真时长、原业务间隔、攻击窗口、DoS5000预算与单次 Replay 规则沿用 V18_FINAL；不存在更改阈值、核心密码协议、评估定义、Person-A 或业务流方向。
