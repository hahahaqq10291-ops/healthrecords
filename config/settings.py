"""
Configuration settings for the Health Record Management System
"""
import os

# Project root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# Database
DATABASE_PATH = os.path.join(PROJECT_ROOT, 'data', 'student_health.db')

# Static and Template folders
TEMPLATE_FOLDER = os.path.join(PROJECT_ROOT, 'templates')
STATIC_FOLDER = os.path.join(PROJECT_ROOT, 'static')

# Upload directories
BACKUP_DIR = os.path.join(PROJECT_ROOT, 'backups')
DOCUMENTS_DIR = os.path.join(PROJECT_ROOT, 'documents')
LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')

# File upload configuration
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx', 'xlsx', 'xls'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Flask Configuration
DEBUG = True
SECRET_KEY_FILE = os.path.join(PROJECT_ROOT, 'config', '.secret_key')

# Ensure required directories exist
os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(DOCUMENTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
