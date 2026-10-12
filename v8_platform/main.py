import uvicorn
from app.app import app


if __name__ == "__main__":
    print("仿真后端启动中...")
    print("API 文档: http://127.0.0.1:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
