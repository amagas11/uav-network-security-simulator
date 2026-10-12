# V21 Windows PowerShell 启动说明

将源码 ZIP 解压到独立的 `无人机网络攻防仿真平台_V21` 目录，不与旧版合并。需要 Python 3.11 或更新版本、Node.js 20.19 或 22.12 及以上版本。

## 首次安装与后端

在新目录打开 PowerShell：

```powershell
Set-Location .\v8_platform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pip install -r ..\person_a_crypto\upstream\requirements-crypto.txt
python -m uvicorn app.app:app --host 127.0.0.1 --port 8113
```

另一个终端检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8113/api/health
Invoke-RestMethod http://127.0.0.1:8113/api/runs/current
```

未创建运行时 current 可能返回空状态。运行状态保存在本版后端进程内存；重启后没有当前运行。按需导出位于本版 `v8_platform\outputs`。

## 首次前端构建与生产预览

另一个 PowerShell 从 V21 根目录进入：

```powershell
Set-Location .\v8_platform\UAV-project\UAV-project
npm ci
npm run test:closure
npm run type-check
npm run build
npm run preview -- --host 127.0.0.1 --port 4184 --strictPort
```

访问 http://127.0.0.1:4184 。正式路由为 `/`、`/spoofing`、`/fdi`、`/dos`、`/eavesdropping`、`/replay`。开发与预览的 `/api` 代理均指向8113。

## 下次快速启动

后端终端在 `v8_platform`：

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.app:app --host 127.0.0.1 --port 8113
```

前端终端在 `v8_platform\UAV-project\UAV-project`：

```powershell
npm run preview -- --host 127.0.0.1 --port 4184 --strictPort
```

源码修改后须重新 `npm run build`。交付不含 node_modules 或 dist，需要首次安装构建。

## 端口隔离与停止

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8113,4184 -ErrorAction SilentlyContinue | Select-Object LocalPort,OwningProcess
```

端口被占用时不要结束未知进程；先停止本版或明确选择其他端口，并同时更新代理。停止：在各自启动终端按 Ctrl+C。旧版8112/4183不受影响。本版浏览器采样命名空间为 `uav-sim-v21:runtime-metric-history:`，按run_id隔离，刷新只恢复已采样点，不补造历史曲线。

## 校验与测试

`SOURCE_MANIFEST_V21.json` 校验正式源码；`V21_SHA256.json` 校验交付包。实际测试、运行JSON和截图见 `V21_VERIFICATION.zip`。后端完整测试在 `v8_platform` 执行 `python -m pytest -q`；Person-A在 `person_a_crypto\upstream` 执行同一命令。依赖首次安装未在全新Windows机器上复验，使用锁文件与依赖清单；本轮实际服务、构建和路由已在验证环境运行。
