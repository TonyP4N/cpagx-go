"""
Entry points for CPAG Generator
Contains unified app management
"""

from .app import create_fastapi_app, VERSION_CONFIG

__all__ = ['create_fastapi_app', 'VERSION_CONFIG']
