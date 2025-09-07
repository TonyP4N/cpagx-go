#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPAG Generator Unified Application Entry Point
Support for multi-version FastAPI applications and Celery tasks
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any

"""
Use version directories as standard packages, removing dynamic sys.path injection
"""

# Version configuration
VERSION_CONFIG = {
    "v1": {
        "port": 8000,
        "enabled": True,
        "name": "Version 1.0",
        "description": "Basic Version - PCAP and CSV file processing"
    },
    "v2": {
        "port": 8002,
        "enabled": True,
        "name": "Version 2.0", 
        "description": "Enhanced Version - ENIP/CIP protocol, Neo4j integration"
    }
}

def get_version_config():
    """Get version configuration"""
    # 尝试从配置文件加载
    config_paths = [
        Path("../../configs/versions.json"),
        Path("../configs/versions.json"),
        Path("configs/versions.json")
    ]
    
    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"加载配置文件失败: {e}")
    
    return {"versions": VERSION_CONFIG}

def create_fastapi_app(version: str):
    """创建指定版本的FastAPI应用"""
    if version == "v1":
        from api.v1.app import app
        return app
    elif version == "v2":
        from api.v2.app import app
        return app
    else:
        raise ValueError(f"不支持的版本: {version}")

def create_celery_app():
    """创建Celery应用"""
    try:
        from infrastructure.celery_app import celery_app
        return celery_app
    except ImportError:
        print("警告: Celery应用不可用")
        return None

# 导出Celery应用（用于Celery Worker和Beat）
celery = create_celery_app()

# 导出版本配置
config = get_version_config()

if __name__ == '__main__':
    import uvicorn
    
    # 获取要启动的版本
    version = os.getenv('CPAG_VERSION', 'v1')
    port = int(os.getenv('PORT', VERSION_CONFIG[version]['port']))
    
    print(f"启动 {version} 版本服务 (端口: {port})")
    
    # 创建并启动应用
    app = create_fastapi_app(version)
    uvicorn.run(app, host="0.0.0.0", port=port)
