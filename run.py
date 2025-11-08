#!/usr/bin/env python3
"""
Simple run script for CVEhive
Usage: python run.py
"""

from app import app

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080) 