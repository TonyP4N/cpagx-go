FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制requirements文件
COPY requirements.txt requirements-prod.txt ./

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements-prod.txt

# 复制应用代码
COPY . .

# 创建必要的目录
RUN mkdir -p outputs uploads

# 设置start_all.sh为可执行
RUN chmod +x start_all.sh

# 暴露端口
EXPOSE 8000 8002

# 健康检查 - 检查两个版本的服务
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health && curl -f http://localhost:8002/health || exit 1

# 使用start_all.sh启动两个版本的服务
CMD ["./start_all.sh"]
