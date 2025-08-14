#!/usr/bin/env python3
"""
CPAG Generator Service Entry Point
支持通过环境变量选择运行v1或v2版本
"""

import os
import sys
import uvicorn
from pathlib import Path

def get_version():
    """获取要运行的版本"""
    version = os.getenv('CPAG_VERSION', 'v1').lower()
    if version not in ['v1', 'v2']:
        print(f"警告: 不支持的版本 {version}，使用默认版本 v1")
        version = 'v1'
    return version

def setup_version_path(version):
    """设置版本路径"""
    version_path = Path(f"versions/{version}")
    if not version_path.exists():
        raise FileNotFoundError(f"版本 {version} 不存在: {version_path}")
    
    # 将版本路径添加到Python路径
    sys.path.insert(0, str(version_path))
    print(f"加载版本: {version} 从路径: {version_path.absolute()}")
    return version_path

def main():
    """主函数"""
    try:
        # 获取版本
        version = get_version()
        print(f"启动 CPAG Generator 服务 - 版本: {version}")
        
        # 设置版本路径
        version_path = setup_version_path(version)
        
        # 导入对应版本的应用
        from app import app
        
        # 获取配置
        host = os.getenv('HOST', '0.0.0.0')
        port = int(os.getenv('PORT', '8000'))
        
        print(f"服务配置: {host}:{port}")
        print(f"版本路径: {version_path.absolute()}")
        
        # 启动服务
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info"
        )
        
    except FileNotFoundError as e:
        print(f"错误: {e}")
        sys.exit(1)
    except ImportError as e:
        print(f"导入错误: {e}")
        print("请确保版本目录中包含必要的文件 (app.py, pcap_service.py, csv_service.py)")
        sys.exit(1)
    except Exception as e:
        print(f"启动失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
