# 无人机安全攻防仿真平台

后端 FastAPI + 前端 Vue，在仿真信道上演示伪装、窃听、DoS、FDI、重放的注入、检测与防御。

说明文档已集中到 [docs/](docs/README.md)。

## 启动

```text
python main.py
```

API 文档：`http://127.0.0.1:8000/docs`

前端见 [docs/UAV前端部署说明.md](docs/UAV前端部署说明.md)。

## 人员 A 密码库

代码在 `crypto/`。包根是 `无人机/`（`from crypto...`）。这是可安装、可单测的库，**没有接到**本仓库仿真主路径。

- Python **3.11**。不要用本仓库里已损坏的 `.venv`。
- `python main.py` 与 `UAVNode.encrypt_packet` **仍是旧仿真**（Base64 伪装），不是这套库。
- 给 `无人机网络攻防仿真平台_V1/` 用时 **import 这份** `crypto/`，不要复制一份进去。

安装与密码单测（不要把 `test_nr_channel_model.py` / `test_traffic_model.py` 当本库验收）：

```text
cd e:\project_cursor\uav_task\无人机
py -3.11 -m pip install -r requirements-crypto.txt
py -3.11 -m pytest tests/test_aead.py tests/test_key_provider.py tests/test_identity.py tests/test_skg.py tests/test_skg_eve.py tests/test_credentials.py tests/test_vectors.py -q
```

