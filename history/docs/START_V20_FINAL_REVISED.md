# V20_FINAL_REVISED Windows PowerShell 启动说明

将源码 ZIP 解压到新的 `无人机网络攻防仿真平台_V20_FINAL_REVISED` 目录，禁止与 V20_FINAL 合并。本版不依赖旧版本服务。

## 后端

在新目录的 `v8_platform` 打开 PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pip install -r ..\person_a_crypto\upstream\requirements-crypto.txt
python -m uvicorn app.app:app --host 127.0.0.1 --port 8112
```

健康检查：http://127.0.0.1:8112/api/health 。当前运行保存在此后端进程内存中，重启后没有当前运行。导出文件在新目录的 `v8_platform\outputs`，不写入 V20_FINAL。

## 生产前端

另一个 PowerShell 进入新目录的 `v8_platform\UAV-project\UAV-project`：

```powershell
npm ci
npm run test:closure
npm run type-check
npm run build
npm run preview -- --host 127.0.0.1 --port 4183 --strictPort
```

访问 http://127.0.0.1:4183 。开发和预览代理均指向 8112。浏览器趋势历史使用 `uav-sim-v20-final-revised:runtime-metric-history:`，按运行 ID 隔离，不虚构刷新前缺失的采样。

## 隔离与停止

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8112,4183 -ErrorAction SilentlyContinue | Select-Object LocalPort,OwningProcess
```

端口被占用时不要结束未知进程。V20_FINAL 原启动入口仍为其原文档（8111/4182）；本版为 8112/4183，互不覆盖。停止各自服务：在启动它的终端按 Ctrl+C。交付不包含持续在线服务。

## 检测和数据范围

正式前端显式配置 Flooding：仅 DoS 专项启用；其他专项关闭 Flooding 告警，但仍保留接收速率观测、基础 HMAC 和重放安全处理。旧 API 不提供 `flooding_detection_enabled` 时保持综合检测。未启用检测器的性能评价为 N/A，不代表零误报。

Spoofing/FDI 都基于真实合法报文捕获副本后额外注入，原件继续传输；两者分别修改声明身份和遥测业务内容，不重算合法身份 HMAC。Eve 是场景设定的被动监听者，不是在线定位结果。窃听接收成功率只针对评价窗口解码事件，不代表所有生成业务交付成功。

源码清单以 `SOURCE_MANIFEST_V20_FINAL_REVISED.json` 为准，历史启动说明和旧清单不作为当前版本验收依据。测试、实际 API 和截图在独立验证包中。
