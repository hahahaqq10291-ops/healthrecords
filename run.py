"""
Application Entry Point
Run this script to start the Flask development server
"""
import os
import sys

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from app import app

if __name__ == '__main__':
    # Run Flask app in debug mode
    app.run(debug=True, host='0.0.0.0', port=5000)
