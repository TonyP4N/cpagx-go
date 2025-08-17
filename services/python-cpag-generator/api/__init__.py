"""
API layer for CPAG Generator
Contains v1 and v2 API implementations
"""

from .v1.app import app as v1_app
from .v2.app import app as v2_app

__all__ = ['v1_app', 'v2_app']
