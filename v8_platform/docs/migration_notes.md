# V1 迁移说明

## 规范入口

根目录是唯一规范代码树：`main.py`、`app/`、`Manager/`、`swarm_sim/`、`tools/` 和 `UAV-project/UAV-project/`。嵌套 `无人机/` 是历史镜像，不参与包发现或运行；保留它是为了避免未经授权删除既有资料。后续修改不得继续双写新功能。

## Python

安装：`python -m pip install -e ".[dev]"`。启动 API：`python main.py`。无 GUI 批量运行：

```powershell
python -m tools.run_experiment --output-dir outputs/batch --seed 42 --seed 43
```

原 `SimulationManager` 已变为兼容 facade，权威状态由 `PlatformRuntime` 持有。新代码不再直接组合旧 attack/channel/detector 类。

## API

新客户端使用：

- `POST /api/runs` 创建；`POST /api/runs/start|pause|resume|stop|reset` 改变生命周期。
- `GET /api/runs/status`、`GET /api/runtime`、`GET /api/gcs/topology`、`GET /api/observations/{id}` 只读。
- `POST /api/debug/step` 是显式调试操作。
- `POST /api/attacks/schedule`、`POST /api/defense/actions`、`POST /api/probes` 是显式写操作。
- `GET /api/evaluation` 是独立离线真值视图。

旧 `/api/init`、`/api/attack`、`/api/step`、listen/metrics/defense 路径继续可用；`GET /api/step` 仅因旧客户端兼容保留，标记 deprecated。新前端轮询绝不调用它。

## 密码学标识

V1 主路径使用 `cryptography` AES-GCM，且清楚标明 mock key 非 SKG。旧 `UAVNode.encrypt_packet` 的 Base64 兼容逻辑已改名为 `BASE64_TEST_ENCODING_NOT_ENCRYPTION`，`security_level=NONE`；禁止将其用于保密性结论。

## 数据

旧单步混合响应不可作为训练数据。C 必须使用 `DatasetExporter` 输出的 V1 run 目录；online `events.jsonl` 与 truth `labels.jsonl` 不得合并后再喂给在线模型。生成数据、日志、模型和前端构建产物均由 `.gitignore` 排除。

## 前端

新 Dashboard 轮询 `/runs/status` 与 `/runtime`；只有运行完成后加载 `/evaluation`。在线区只展示 GCS 收到的事件/报告，离线区明确标注 truth scope。旧组件仍保留以便比对，但不再挂载。

