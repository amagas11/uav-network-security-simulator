# V18 REFINED 独立启动

解压本版源码包至独立目录，不合并、不覆盖 V18_FINAL。

终端 1，工作目录 `v8_platform/`：

```powershell
python -m pip install -e ".[dev]"
python -m pip install -r ../person_a_crypto/upstream/requirements-crypto.txt
python -m uvicorn app.app:app --host 127.0.0.1 --port 8109
```

终端 2，工作目录 `v8_platform/UAV-project/UAV-project/`：

```powershell
npm ci
npm run build
npm run preview -- --host 127.0.0.1 --port 4180 --strictPort
```

前端 http://127.0.0.1:4180；后端 http://127.0.0.1:8109；代理与浏览器采样命名空间均独立。
运行状态存于本版后端进程内存；停止方式为两个终端分别 Ctrl+C。
V18_FINAL 保留原目录、原 ZIP、原端口 8108/4179 与原启动说明 `START_V18.md`。

FDI 高度为真实节点高度加确定性、有界的传感器测量误差，不代表爬升轨迹。
DoS 接收速率是成功解码后、HMAC 过滤前的接收窗口观测，不是配置发送速率，也不是 GCS 收到的网络报告。
短时在线演示不等同于万条业务的大规模验证。
