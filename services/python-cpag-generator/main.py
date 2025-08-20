#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPAG Generator Main Entry Point

"""

import os
import sys
from pathlib import Path

# 添加当前目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from entrypoints.app import create_fastapi_app, VERSION_CONFIG

def main():
    # 获取要启动的版本
    version = os.getenv('CPAG_VERSION', 'v1')
    port = int(os.getenv('PORT', VERSION_CONFIG[version]['port']))
    
    print(f"Starting CPAG Generator {version} (Port: {port})")
    
    # 创建并启动应用
    app = create_fastapi_app(version)
    
    # 导入uvicorn并运行
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == '__main__':
    main()
