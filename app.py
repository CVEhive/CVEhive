#!/usr/bin/env python3
"""
CVEhive Flask Application
Main entry point for the CVEhive web application.
"""

from flask import Flask
from app.config import Config
from app.models.base import init_db
from app.frontend.routes import frontend_bp
from app.api.routes import api_bp
from app.utils.logger import setup_logging

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Setup logging
    setup_logging(Config.LOG_LEVEL, Config.LOG_FILE)
    
    # Initialize database
    init_db()
    
    # Register blueprints
    app.register_blueprint(frontend_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    
    return app

# Create the app instance
app = create_app()

if __name__ == '__main__':
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    ) 