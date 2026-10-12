# 无人机网络攻防仿真平台 V14 交付清单

本目录是 V14 正式演示平台的规范实现。交付包继续使用内部 producer
`platform-v7` 与数据 schema `3.2.0`；版本名称变化不改变协议、数据或攻击语义。

## 当前正式能力

- 六个正式前端路由：系统总览、报文伪装、FDI、DoS/Flooding、窃听和重放；
- 五类攻击固定为 SPOOFING、EAVESDROPPING、DOS/FLOODING、FDI、REPLAY；
- Spoofing、Flooding、FDI、Replay 使用 per-device Application HMAC；
- Eavesdropping 使用 Person-A CSI/SKG 会话密钥与 AES-GCM；
- FastAPI、Direct Runtime、Manager、Batch、RL 保持统一 Runtime factory 边界；
- Online Runtime、仿真配置/真值、Offline Evaluation 在 API 与界面中分层展示；
- DatasetValidator、LeakageAudit、回放窗口、密钥生命周期与五攻击评价保持可测试。

DoS 不包含 JAMMING。C 侧 BiLSTM、Dueling Q-learning、RFF 模型训练与 readiness
属于历史规划，不是 V14 正式演示范围；相关历史契约文档仅为追溯保留。

## 主要目录

- `app/`、`main.py`：FastAPI 正式应用入口，默认注入 Person-A security bundle；
- `swarm_sim/`：通信、PHY、攻击、检测、防御、报告、评价与数据导出；
- `Manager/`、`UAVNode/`、`network/`、`NRChannel/`：运行与兼容层；
- `tests/`：unit、integration、acceptance 与 regression；
- `UAV-project/UAV-project/`：Vue 3 + TypeScript 正式前端；
- `docs/`：当前语义、接口、冻结边界和历史追溯文档。

Person-A 的唯一上游副本位于交付包同级路径
`person_a_crypto/upstream/`，B 侧仅通过 integration adapter 接入。

## 本轮最终验证

```text
python -m compileall -q swarm_sim Manager app tools tests
python -m pytest -q
cd UAV-project/UAV-project
npm run test:closure
npm run type-check
npm run build
```

结果：主工程 `413 passed, 2 warnings`；Person-A upstream `37 passed`；前端
closure、type-check、production build 全部通过。真实 FastAPI + production preview
完成六路由、五场景、三种 Replay、刷新恢复、快速切页、服务停机/恢复以及
1366×900 / 1920×1080 浏览器验证，Console/Vue/ECharts 运行错误为 0。

## 不包含的生成物

最终 ZIP 不包含 `.git`、`node_modules`、`dist`、`__pycache__`、`.pytest_cache`、
运行数据、浏览器截图、调试输出或其他可重建缓存。

## 外部成熟度边界

当前 Person-A 资产状态仍为 `INTEGRATED_DEVELOPMENT`。V8_DEFAULT/真实 RF 条件下的
最终 SKG 外场成熟度不因演示前端通过而提升；正式真实实验仍依赖外部 A 资产和真实数据。
