#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CPAG Generator Main Entry Point

"""

import os
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from entrypoints.app import create_fastapi_app, VERSION_CONFIG

def main():
    version = os.getenv('CPAG_VERSION', 'v1')
    port = int(os.getenv('PORT', VERSION_CONFIG[version]['port']))
    
    print(f"Starting CPAG Generator {version} (Port: {port})")
    
    app = create_fastapi_app(version)
    
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == '__main__':
    main()
