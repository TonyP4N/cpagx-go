FROM python:3.11-slim

WORKDIR /app

# 安装系统依赖并更新安全补丁
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gcc \
    g++ \
    libpcap-dev \
    libffi-dev \
    libssl-dev \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 升级pip和setuptools
RUN pip install --upgrade pip setuptools wheel

# 复制依赖文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 暴露端口
EXPOSE 8000

# 启动命令
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"] 