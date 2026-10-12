# V20_FINAL Windows PowerShell 启动说明

解压 `无人机网络攻防仿真平台_V20_FINAL.zip` 至全新目录，禁止合并或覆盖 V20。
当前正式版本为 V20_FINAL；旧 START_V17/V18/V19/V20 等说明仅为历史资料，不是本版启动入口。

## 后端

在解压后的 `无人机网络攻防仿真平台_V20_FINAL\v8_platform` 打开 PowerShell：

```powershell
python -m pip install -e ".[dev]"
python -m pip install -r ..\person_a_crypto\upstream\requirements-crypto.txt
python -m uvicorn app.app:app --host 127.0.0.1 --port 8111
```

健康检查：http://127.0.0.1:8111/api/health 。运行状态由本后端进程独立保存在内存中，重启后无 active run。依赖、缓存和导出文件仅生成在新版本目录；数据导出位于 `v8_platform\outputs`，不进入正式源码 ZIP。

## 生产前端

另一个 PowerShell 终端进入 `无人机网络攻防仿真平台_V20_FINAL\v8_platform\UAV-project\UAV-project`：

```powershell
npm ci
npm run test:closure
npm run type-check
npm run build
npm run preview -- --host 127.0.0.1 --port 4182 --strictPort
```

访问 http://127.0.0.1:4182 。开发及预览 API 代理均指向 8111；浏览器采样历史采用独立 `uav-sim-v20-final:runtime-metric-history:` 命名空间，按 run_id 隔离，最多160点。源码包不含 node_modules/dist，首次使用必须安装依赖并构建。
本轮环境：Windows、Python 3.13.1、Node 24.19.0、Chrome 154。Node 支持范围以 package.json 为准。

## 端口和停止

启动前可检查端口：

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8111,4182 -ErrorAction SilentlyContinue | Select-Object LocalPort,OwningProcess
```

若已有 V20 或其它服务占用端口，不结束未知进程，先由其所有者停止服务。本版不依赖旧版服务。V20 原目录、ZIP和启动方式未改；两版使用相同默认端口时不能同时启动，必须分别停止各自终端中的服务后切换版本。
停止本版：在后端和前端两个终端分别按 Ctrl+C。验收临时服务已停止，不保证 URL 在交付后仍在线。

## 正式科研模型与统计

Spoofing 和 FDI 均保留合法原报文；External 捕获真实副本后额外注入攻击副本。前者只改声明身份，后者只改遥测业务字段，不掌握设备认证密钥，不重新计算原 Application HMAC。未宣称攻击已改变飞行状态。
FDI 可以真实触发接收总到达速率告警；总览按 GCS 可见报告/汇总和执行动作分别显示，不删除跨类别告警。窃听“评价窗口解码接收成功率”不是全部生成业务的交付比例。详见验证包的逐窗口和分母审计。
源码文件校验以 `SOURCE_MANIFEST_V20_FINAL.json` 为唯一新版依据；历史哈希清单位于 `history\manifests`。验证证据单独在 `V20_FINAL_VERIFICATION.zip`。
