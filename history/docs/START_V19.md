# V19 启动说明

解压“无人机网络攻防仿真平台_V19.zip”得到独立的“无人机网络攻防仿真平台_V19”目录。不要覆盖 V18_REFINED。两个版本应分别使用各自目录、端口和浏览器 origin。

## 后端

在 V19 的 v8_platform 目录打开 PowerShell：

```powershell
python -m pip install -e ".[dev]"
python -m pip install -r ../person_a_crypto/upstream/requirements-crypto.txt
python -m uvicorn app.app:app --host 127.0.0.1 --port 8110
```

API：http://127.0.0.1:8110/api/health 。Person-A 库在本包 person_a_crypto/upstream，按正式 API 组合根加载，不依赖 V18 服务。

## 前端

另一个终端进入 V19 的 v8_platform/UAV-project/UAV-project：

```powershell
npm ci
npm run build
npm run preview -- --host 127.0.0.1 --port 4181 --strictPort
```

访问 http://127.0.0.1:4181 。开发及 preview 的 /api 代理均指向 8110。Node 范围沿用 package.json：^20.19.0 或 >=22.12.0。不要在运行浏览器验收时重新构建 dist。

## 独立性、运行数据与停止

V19 后端运行状态存储在本后端进程内存，重启不保留 active run；Reset 产生独立 run。浏览器会话采样使用 uav-sim-v19 命名空间，并按 run_id 隔离。包内不包含运行日志、缓存、node_modules 或 dist。
停止：各终端按 Ctrl+C。端口被占用时先确认所属进程；不要结束未知进程。V18_REFINED 原目录、源 ZIP 及其端口 8109/4180 不被本版本覆盖。

## FDI 能力边界

新默认是明确授权的受控中继链：Follower 2 签名后真实发送给 External，External 解码截获后修改明文遥测、保持原 HMAC，再真实转发给 Leader 1。它不是普通旁路监听者无条件阻断无线原帧。业务 ID 不变，两个物理发射 ID 分开；目标只收到一次版本。External 不持有合法认证密钥。旧 POST_HMAC_PRE_TRANSMISSION 模式仍支持。
