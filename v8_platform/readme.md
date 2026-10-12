# 无人机网络攻防仿真平台

可复现、逐跳、节点局部观测的无人机编队网络安全仿真平台。当前候选版V21_FINAL；启动以根目录 `START_V21_FINAL.md` 为准，使用8114/4185。producer `platform-v7` 与数据契约 `3.2.0` 是兼容标识，不是交付版本号。平台保留在线证据、场景真值与离线评价分层。

当前五类攻击固定为 SPOOFING、EAVESDROPPING、DOS/FLOODING、FDI 和 REPLAY；
不再提供 DOS/JAMMING 攻击场景。Spoofing/Flooding/FDI/Replay 的单独演示使用独立
per-device HMAC-SHA-256 应用认证且默认 AES off；Eavesdropping 使用 Person-A
CSI/SKG 会话密钥与 AES-GCM。详细顺序与证据见
`docs/v10_five_attack_hmac_closure.md`。

## 快速开始

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m uvicorn app.app:app --host 127.0.0.1 --port 8114
```

API 文档：`http://127.0.0.1:8114/docs`。

前端：

```powershell
cd UAV-project/UAV-project
npm ci
npm run build
npm run preview -- --host 127.0.0.1 --port 4185 --strictPort
```

## 无 GUI 批量实验

```powershell
python -m tools.run_experiment `
  --output-dir outputs/batch `
  --seed 42 --seed 43 `
  --duration-s 10 --step-s 0.2 --node-count 6
```

可用 `--attack-plan path/to/attacks.json` 与 `--normal-disturbance-plan path/to/normal.json` 同时加载攻击/正常对照计划；`--calibration-profile path/to/profile.json` 使用经严格校验的 CalibrationProfile。每次实例输出唯一 run ID 和目录；重复 seed 仍不覆盖，但相同配置的语义事件流可复现。每个 run 自动执行 validator。

默认输出 maturity 为 `DEVELOPMENT` 并记录 mock/test security provider。正式数据
流程可加 `--require-formal-security --dataset-maturity FORMAL`；当 A 的正式
provider 尚未接入时该命令会拒绝运行，不会把 mock 数据冒充正式实验数据。

## 关键边界

- 所有协议、攻击和检测时间只使用 `sim_time_s`；墙钟只可用于 API 后台运行节奏。
- 每个 hop 都经过发送队列、物理层、接收队列和转发队列；同一消息保留 `message_id`。
- `events.jsonl` 只含 observer 当时可见字段；`labels.jsonl` 只供离线 evaluator。
- Direct/unit-test 的裸 `PlatformRuntime`/`PlatformRuntimeFactory` 默认仍使用明确标记的
  test provider；正式 FastAPI/UI composition root 默认注入 Person-A bundle，使用
  `V8_DEFAULT` Probe、网络承载 SKG 与 AES-GCM，且不预加载测试 key。该 A 资产 maturity
  仍是 `INTEGRATED_DEVELOPMENT`。
- V21_FINAL 正式演示不纳入 C 侧模型训练、readiness 或 RFF 模型展示；仓库中保留的 C 接口与文档是历史集成契约，不是本版正式演示的必做项或验收门槛。
- Schema 2.x 数据不会被改名冒充 3.2；`python -m tools.migrate_dataset --input ... --output ...` 会生成可核验 incompatibility report。

## 技术文档与历史合同

以下版本命名文档记录历史技术合同，不能代替本轮验证。当前正式场景、计数与交付结果以包根目录 README、PACKET_COUNTER_DEFINITIONS、FINAL_DELIVERY_SUMMARY 和 V21_FINAL_VERIFICATION 为准。

- `docs/platform_architecture_v1.md`：总体架构与在线/离线边界
- `docs/v10_five_attack_hmac_closure.md`：当前五类攻击、应用 HMAC、接收顺序与评价合同
- `docs/v11_remaining_closure.md`：Evaluation、Flooding ingress/emitter 与正式 Web Person-A 收口
- `docs/v7_final_functional_closure.md`：V7 最终功能缺口、反例、实现与冻结证据
- `docs/calibration_runtime_semantics.md`：校准 target/control 与真实 Runtime 作用公式
- `docs/runtime_dependency_integration.md`：Direct/Manager/API/Batch/RL 的依赖工厂合同
- `docs/final_completion_boundary.md`：B 软件完成与外部资产边界
- `docs/legacy_dataset_policy.md`：schema-2 历史开发数据策略
- `docs/data_schema_v1.md`：冻结 schema 3.2 数据契约（文件名为兼容保留）
- `docs/schema_version_decision_v7.md`：schema 3.2 minor-version 判断与 legacy 数据策略
- `docs/c_final_training_contract.md`、`docs/schema_contract_for_C.md`：历史 C 侧接口契约，不纳入 V16 正式演示范围
- `docs/v6_final_closure_plan.md`：V6 反例、修复、测试和最终闭环追踪
- `docs/v6_exhaustive_requirement_audit.md`：三份原始需求的穷尽式责任、运行路径和测试审计
- `docs/v6_final_closure_patch.md`：最后 model/report/eaves/calibration/RL/migration 缺口追踪
- `docs/final_scenario_mechanism_matrix.md`：21 个当前场景的数据合同与机制证据矩阵
- `docs/v3_final_convergence_plan.md`：V3 缺口、根因、修复和验收追踪
- `docs/v4_semantic_convergence_plan.md`：V4 数据语义、评价 scope、模型闭环和场景矩阵追踪
- `docs/a_integration_interface.md`：A 无线观测/密钥接入
- `docs/c_integration_interface.md`：历史 C 侧集成记录，不纳入 V16 正式演示范围
- `docs/migration_notes.md`：旧代码/API 迁移
- `docs/requirement_traceability_matrix.md`：逐项需求追踪
- `docs/test_report.md`：可复核验收命令与结果
- `docs/final_status_report.md`：完成项与外部阻塞项

根目录为规范实现；嵌套 `无人机/` 仅为历史镜像，不参与 Python 包发现。

## Person-A 融合 profile 边界

Person-A factory 默认继续使用原始 `V8_DEFAULT` Probe。A v0.1 SKG adapter 的成功闭环
测试必须显式选择 `PERSON_A_V01_COMPAT_TEST`；该模式是 TEST_ONLY，会进入 run metadata
和 readiness blocker。双方 CONFIRM 经 pending/cross-verify 后才成对提交，重复
pair/session/target-epoch rekey 返回 `existing_rekey_in_progress`。详见
`docs/person_a_skg_closure_patch.md`。
