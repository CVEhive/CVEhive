"""
CVEhive - CVE Search Engine with Exploit Validation
A comprehensive platform for security researchers to find validated CVE exploits.
"""

__version__ = "1.0.0"
__author__ = "CVEhive Team"

import os
from flask import Flask
from app.config import Config
from app.models.base import init_db
from app.utils.logger import setup_logging

def create_app():
    """Create and configure the Flask application."""
    # Get the path to the project root (parent of app directory)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(project_root, 'templates')
    static_dir = os.path.join(project_root, 'static')
    
    app = Flask(__name__, 
                template_folder=template_dir,
                static_folder=static_dir)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Setup logging
    setup_logging(app.config.get('LOG_LEVEL', 'INFO'))
    
    # Initialize database
    init_db(app)
    
    # Register blueprints
    from app.frontend import frontend_bp
    from app.api import api_bp
    from app.admin import admin_bp
    
    app.register_blueprint(frontend_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)
    
    return app

# Create app instance for imports
app = create_app() 