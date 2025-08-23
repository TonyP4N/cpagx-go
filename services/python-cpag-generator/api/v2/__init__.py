"""
CPAG Generator v2 API
Enhanced CPAG generation with advanced features
"""

from .app import app
from .tasks import generate_cpag

__all__ = ['app', 'generate_cpag']


