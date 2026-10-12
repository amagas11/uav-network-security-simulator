# V18 独立启动

解压 `无人机网络攻防仿真平台_V18_FINAL.zip`，以其顶层目录为 V18 工作目录。不要把文件合并到 V17。

后端（终端 1，工作目录 `v8_platform/`）：

```powershell
python -m pip install -e .
python -m pip install -r requirements-crypto.txt
python -m uvicorn app.app:app --host 127.0.0.1 --port 8108
```

前端（终端 2，工作目录 `v8_platform/UAV-project/UAV-project/`）：

```powershell
npm ci
npm run build
npm run preview -- --host 127.0.0.1 --port 4179 --strictPort
```

前端 http://127.0.0.1:4179；后端 http://127.0.0.1:8108。API 代理仅指向 V18 后端。浏览器采样缓存命名空间为 uav-sim-v18；运行状态在此后端进程内存中。两终端 Ctrl+C 停止。

V17 原目录与 ZIP 不变，其旧启动说明为 START_V17.md（端口 8107/4178）。两版可以独立运行；不要混用 API 地址。短时演示不是 10000 条业务的大规模实验。
