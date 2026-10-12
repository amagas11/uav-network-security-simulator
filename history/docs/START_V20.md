# V20 独立启动说明

解压源码ZIP，在独立“无人机网络攻防仿真平台_V20”目录操作，不覆盖V19。

## 后端

进入 `v8_platform`：

```powershell
python -m pip install -e ".[dev]"
python -m pip install -r ../person_a_crypto/upstream/requirements-crypto.txt
python -m uvicorn app.app:app --host 127.0.0.1 --port 8111
```

后端 http://127.0.0.1:8111/api/health 。运行状态在该后端进程内存中，重启后不保留active run。

## 前端

另一终端进入 `v8_platform/UAV-project/UAV-project`：

```powershell
npm ci
npm run build
npm run preview -- --host 127.0.0.1 --port 4182 --strictPort
```

访问 http://127.0.0.1:4182 。开发和preview的API代理都指向8111，浏览器会话缓存为uav-sim-v20并按run_id隔离。Node支持沿用package.json：^20.19.0或>=22.12.0。本轮实测Node v24.19.0 / Python3.13.1。

停止：各终端Ctrl+C。端口占用时确认所属进程，不结束未知服务。V19保持原目录和8110/4181，不共享运行进程或浏览器缓存。

## 正式FDI模型

Follower 2正常生成、签名并发送遥测；External捕获实际报文，保持合法声明身份及原Application HMAC，只修改副本业务内容，再额外发送至Leader 1。原报文未被主动拦截，两者接收和处置分别记录。当前小幅高度测量扰动用于完整性检测，不代表目标飞行状态已被改变。旧兼容模式不是正式默认。

源码包不含node_modules、dist、缓存、日志或临时审计结果。验收截图和真实API数据另在V20_VERIFICATION.zip。
