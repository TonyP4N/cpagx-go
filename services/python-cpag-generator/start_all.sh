#!/bin/bash

echo "Starting CPAG Generator Services..."
echo "=================================="

# 启动v1服务
echo "Starting v1 service on port 8000..."
export CPAG_VERSION=v1
export PORT=8000
python main.py &
V1_PID=$!

# 等待v1服务启动
sleep 3

# 启动v2服务
echo "Starting v2 service on port 8002..."
export CPAG_VERSION=v2
export PORT=8002
python main.py &
V2_PID=$!

# 等待v2服务启动
sleep 3

echo "=================================="
echo "Services started:"
echo "v1 service PID: $V1_PID (port 8000)"
echo "v2 service PID: $V2_PID (port 8002)"
echo ""
echo "To stop services, run:"
echo "kill $V1_PID $V2_PID"
echo "=================================="

# 等待用户中断
wait
