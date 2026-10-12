# Independent V17 startup

Work directory: extracted V17_FINAL/v8_platform. Python 3.13.1 and Node 24.19.0 were used for verification. Install Python dependencies from pyproject.toml and frontend dependencies using npm ci.

Backend: `python -m uvicorn app.app:app --host 127.0.0.1 --port 8107`

Frontend work directory: v8_platform/UAV-project/UAV-project. Run `npm run build`, then `npm run preview -- --host 127.0.0.1 --port 4178 --strictPort`.

Frontend http://127.0.0.1:4178; backend http://127.0.0.1:8107. V17 Vite proxy targets 8107. Runtime state is in this backend process, not the V16 process. Browser metric samples use sessionStorage prefix uav-sim-v17. Stop each service with Ctrl+C in its own terminal. Runtime disappears when backend stops. No dependency on a running V16 service.

V16_FINAL remains unchanged: its own extracted v8_platform directory, backend `python -m uvicorn app.app:app --host 127.0.0.1 --port 8000`, frontend build/preview on its original port (4173) and API proxy 8000. Do not install/build into protected archival source during comparison. Verification additionally built the pristine V16 frontend in a temporary V17 audit copy and served it on 4106 against the independent V16 backend; Python bytecode writes in original V16 were disabled and logs redirected into V17. Stop V16 independently with Ctrl+C. V17 source ZIP excludes node_modules, dist, caches, audit evidence and logs.
