"""
CVEhive Admin Panel
Provides administrative interface for managing CVEs, PoCs, and validation processes.
"""

from flask import Blueprint

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

from app.admin import routes 