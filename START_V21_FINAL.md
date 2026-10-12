# V21_FINAL Windows PowerShell 启动

源码ZIP解压到独立V21_FINAL目录，不要与旧版合并。需要Python 3.11+、Node.js 20.19或22.12+。

## 首次安装与后端

从V21_FINAL根目录在PowerShell执行：

```powershell
Set-Location .\v8_platform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pip install -r ..\person_a_crypto\upstream\requirements-crypto.txt
python -m uvicorn app.app:app --host 127.0.0.1 --port 8114
```

## 前端生产构建与启动

另一个PowerShell从V21_FINAL根目录执行：

```powershell
Set-Location .\v8_platform\UAV-project\UAV-project
npm ci
npm run test:closure
npm run type-check
npm run build
npm run preview -- --host 127.0.0.1 --port 4185 --strictPort
```

访问 http://127.0.0.1:4185 。六路由为 `/`、`/spoofing`、`/fdi`、`/dos`、`/eavesdropping`、`/replay`。开发及预览API代理均指向8114。

## 健康与端口检查

```powershell
Invoke-RestMethod http://127.0.0.1:8114/api/health
Invoke-RestMethod http://127.0.0.1:8114/api/runs/current
Get-NetTCPConnection -State Listen -LocalPort 8114,4185 -ErrorAction SilentlyContinue | Select-Object LocalPort,OwningProcess
```

没有运行时current为空。端口冲突不要结束未知服务；另选端口须同步更新Vite代理。后端状态在本进程内存中，重启为空。源码包不含依赖、dist、运行数据及截图。

## 下次快速启动与停止

后端在v8_platform激活上述venv后运行同一uvicorn命令；前端在v8_platform\UAV-project\UAV-project运行同一preview命令。源码修改须先重新build。各自终端Ctrl+C停止本版，不影响原V21。

本轮实际服务、构建、健康与六路由已验证；依赖复用验证环境，未冒称在全新Windows机器完成首次安装。

源码清单为SOURCE_MANIFEST_V21_FINAL.json。若验证包文本采用ZIP LZMA，请用7-Zip或 `python -m zipfile -e V21_FINAL_VERIFICATION.zip V21_FINAL_VERIFICATION` 解压，再运行包内恢复校验脚本。
