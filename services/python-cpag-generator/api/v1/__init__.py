"""
CPAG Generator v1 API
Simple CPAG generation with basic features
"""

from .app import app
from .tasks import generate_cpag

__all__ = ['app', 'generate_cpag']


