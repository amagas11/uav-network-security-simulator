# V21_FINAL 正式前端部署说明

正式前端位于 `UAV-project/UAV-project/`，使用 Vue 3、TypeScript、Pinia、Vite
与 ECharts。正式入口仅包含系统总览及五个攻击页面；历史组件不在 router/App
import graph 中。

## 环境

- Python 3.11+
- Node.js 20.19+
- npm（依赖版本由 `package-lock.json` 锁定）

## 启动后端

在 `v8_platform/` 中执行：

```text
python -m pip install -e ".[dev]"
python -m uvicorn app.app:app --host 127.0.0.1 --port 8114
```

API 文档为 `http://127.0.0.1:8114/docs`。正式 FastAPI composition root 默认使用
Person-A bundle；不会用预加载测试 key 冒充 SKG。

## 启动开发前端

```text
cd UAV-project/UAV-project
npm ci
npm run dev
```

默认访问 `http://127.0.0.1:5173/`，`/api` 由 Vite 代理到
`http://127.0.0.1:8114`。

## 生产构建与预览

```text
npm run test:closure
npm run type-check
npm run build
npm run preview -- --host 127.0.0.1 --port 4185 --strictPort
```

构建产物位于 `dist/`，它是可重建产物，不包含在源码交付 ZIP 中。部署服务器需要把
六个 SPA 子路由回退到 `index.html`；Vite preview 已支持直接刷新这些路由。

## 正式路由

- `/`
- `/spoofing`
- `/fdi`
- `/dos`
- `/eavesdropping`
- `/replay`

页面只使用当前 `/api/runs*`、`/api/runtime`、`/api/evaluation` 与正式攻击调度接口。
旧 `/api/init`、`/api/attack`、legacy listen API 仅为后端兼容保留，不属于正式前端流程。
