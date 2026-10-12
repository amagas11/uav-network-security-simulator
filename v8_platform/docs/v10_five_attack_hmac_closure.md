# V10 五类攻击与应用层 HMAC 语义闭环

本文件冻结当前 V10 交付树的攻击、检测与数据面反制语义。Person-A 的 CSI/SKG、
AES-GCM、Ed25519 和 credential 实现未修改；应用层 HMAC 是独立的端到端业务认证层。

## 当前攻击集合

| 攻击 | 注入机制 | 在线证据 | 数据面处理 |
|---|---|---|---|
| SPOOFING | 原报文完成 HMAC 后只改 `claimed_src_id` | `APPLICATION_HMAC_FAIL` / `UNKNOWN_DEVICE_KEY` | `DROP_PACKET`，不执行业务 |
| EAVESDROPPING | 被动捕获无线帧 | ciphertext/protection/exposure 统计 | 敏感业务由 Person-A CSI/SKG→AES-GCM 保护 |
| DOS/FLOODING | External 短时发送高频 STATUS 形态报文 | receiver 全来源总到达率超过阈值 | 到达先计数；非法 HMAC 帧逐包 `DROP_PACKET` |
| FDI | 合法报文先生成 HMAC，随后修改业务 payload | `HMAC_MISMATCH` | `DROP_PACKET` / `NO_UPDATE` |
| REPLAY | 原样重发完整历史帧 | HMAC PASS 后由 timestamp/session/window 拒绝 | `DROP_PACKET`，旧业务不重复执行 |

`DOS/JAMMING` 已从 AttackPlan、API、Manager、前端、场景矩阵、规则和 evaluator 当前
能力中删除。PHY 的 noise、generic interference、RSSI/SNR/SINR/PER、CSI 和 normal
low-SNR/packet-loss 扰动仍保留，它们不是 JAMMING 攻击入口。

## Application HMAC 合同

- 算法：HMAC-SHA-256，取前 16 bytes，在线 hex tag 长度为 32。
- key scope：每个合法 device 一把独立 `K_device`；External 没有合法设备 key。
- 密钥只存在于 run-local `ApplicationHmacService`，events、dataset、API、frontend、
  provenance 均只记录非秘密 key ID/算法/结果。
- `MAC_Data` 由唯一函数 `canonical_mac_data()` 生成：
  `direction, device_id, message_type, sequence_no, timestamp_ms,
  payload_length, business_payload`。
- payload 使用 UTF-8 canonical JSON：`sort_keys=True`、固定紧凑 separators；timestamp
  由唯一 `created_time_s` 四舍五入为整数毫秒；比较使用 `hmac.compare_digest()`。
- `application_direction` 是原始业务方向 UPLINK/DOWNLINK，Leader 逐跳转发不修改。
- `Frame.auth_tag` 继续只表示 crypto/AES 认证；应用认证使用独立
  `app_hmac_tag` / `app_hmac_key_id`。
- `SKG_CONTROL` 不适用应用 HMAC，其 RECONCILE/CONFIRM 继续由 Person-A Ed25519
  handshake authentication 保护；在线结果为 `NOT_APPLICABLE`。这避免混淆业务认证
  与 SKG 控制认证。

## 接收端冻结顺序

```text
PHY decode success
  -> receiver-total arrival accounting / FLOODING rate rule
  -> crypto open (仅显式 AES profile)
  -> application HMAC verification
       FAIL/MISSING/UNKNOWN_DEVICE -> DROP, no business update
  -> timestamp freshness
  -> active session/key epoch
  -> sliding ReplayWindow (duplicate/stale/legal reorder)
  -> forwarding or business handler
```

因此 Flooding 攻击帧即使随后 HMAC 失败，也已经进入 receiver 总到达统计；HMAC 失败
不作为 DOS 分类条件。HMAC 的数学结果只输出通用 `AUTH_FAILURE`，不读取
`attack_family`、`runtime_attack_id` 或其它离线 truth 来区分 Spoofing/FDI/Flooding。

## 配置与入口

- `encrypt_sensitive` 默认 `false`。
- 单独演示 SPOOFING、FLOODING、FDI、REPLAY 时 Runtime 固定 AES off；
  EAVESDROPPING 固定 AES on（显式 plaintext exposure control 除外）。
- `flooding_packet_rate_threshold_pps` 默认 8.0，使用
  `traffic_statistics_window_s` 的 receiver-total 窗口。
- `replay_timestamp_freshness_s` 默认 2.0；未来时间戳 fail closed，过期为
  `STALE_TIMESTAMP`。
- `replay_reorder_window_size` 保留滑动窗口语义，窗口内未见过的乱序序号合法。
- Direct Runtime、SimulationManager/FastAPI、Batch 和 RL 使用同一 RunConfig/runtime
  处理链。前端按攻击选择新建对应 encryption profile，不在既有 run 上静默切换。

## 数据与评价

Schema 3.2 以 optional additive 字段记录：
`application_hmac_result`、`application_hmac_failure_reason`、
`application_hmac_key_id`、receiver total count/rate/threshold。离线 labels 保存 mutation、
真实来源与 attack outcome；这些字段不进入 online features。

Evaluator 当前策略：

- Spoofing：目标帧 HMAC 拒绝、DROP、未执行；
- Flooding：receiver-total rate gate + malicious HMAC reject + bounded legitimate harm；
- FDI：POST-HMAC mutation + HMAC reject + no business update；
- Replay：HMAC PASS + timestamp/session/window 拒绝 + no duplicate execution；
- Eavesdropping：ciphertext protection/plaintext exposure，不伪造被动监听在线检测。

## 验收证据

- focused：`tests/acceptance/test_v10_application_hmac_semantics.py` 10 passed；
- current scenario mechanism matrix：21/21 passed；
- full Python suite：398 passed，2 个第三方 deprecation warnings；
- Person-A upstream：37 passed；Person-A integration：46 passed（SKG/AEAD/rekey/attack）；
- frontend：`npm ci`、`npm run type-check`、`npm run build-only` 均 PASS；
- compile/schema/validator/leakage 在最终验收命令中单独复核。

## Change manifest（相对输入 V10 ZIP）

新增：`swarm_sim/application_auth.py`、
`tests/acceptance/test_v10_application_hmac_semantics.py`、本文件。

主要运行代码：`swarm_sim/{adapters,attacks,domain,evaluation,events,leakage,phy,runtime,
scenario_validation,security,simulation}.py`、
`swarm_sim/integrations/person_a/bridge.py`、`app/app.py`、
`Manager/simulationmanager.py`、`attack/{SpoofingAttack,DoSAttack,FDIAttack}.py`、
`network/network.py`、`NRChannel/NRChannel.py`。

前端：`AttackControl.vue`、`Dashboard.vue`、`Map.vue`、`charts/NetworkTopology.vue`。
契约与报告：`dataset/schema.json`、`schema_3_2_example_dataset/*`、`readme.md` 及本轮相关
`docs/` 契约/矩阵/状态/测试文档。测试方面更新了 22 个既有 API、回归、scenario、C gate
和 Person-A 用例文件；未删除测试文件，只退役 JAMMING-only collected cases 并重写旧
Flooding/FDI/Spoofing 断言。Person-A `upstream` 源码 hash 对比无变化。
