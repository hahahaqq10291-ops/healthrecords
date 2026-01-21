from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, make_response
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from functools import wraps
import sqlite3
import os
import csv
import io
import json
import bcrypt
import random
import string
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from pathlib import Path
from encryption_utils import get_encryption_handler, should_encrypt_field

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Environment variables from .env will not be loaded.")

# ---------------------- FLASK APP CONFIG ---------------------- #

# Get project root directory (parent of src/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__, template_folder=os.path.join(PROJECT_ROOT, 'templates'), static_folder=os.path.join(PROJECT_ROOT, 'static'))

# Use persistent secret key (stored in environment or file)
SECRET_KEY_FILE = os.path.join(PROJECT_ROOT, 'config', '.secret_key')
os.makedirs(os.path.dirname(SECRET_KEY_FILE), exist_ok=True)
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(app.secret_key)

# CSRF Protection disabled temporarily for debugging
csrf = CSRFProtect(app)

# Disable CSRF protection globally
app.config['WTF_CSRF_ENABLED'] = False

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# Initialize Flask-Mail
mail = Mail(app)

# Debug: Check email configuration on startup
print("=" * 60)
print("EMAIL CONFIGURATION CHECK:")
print(f"MAIL_SERVER: {app.config.get('MAIL_SERVER')}")
print(f"MAIL_PORT: {app.config.get('MAIL_PORT')}")
print(f"MAIL_USE_TLS: {app.config.get('MAIL_USE_TLS')}")
print(f"MAIL_USERNAME: {'[SET]' if app.config.get('MAIL_USERNAME') else '[NOT SET]'}")
print(f"MAIL_PASSWORD: {'[SET]' if app.config.get('MAIL_PASSWORD') else '[NOT SET]'}")
print(f"MAIL_DEFAULT_SENDER: {app.config.get('MAIL_DEFAULT_SENDER')}")
print("=" * 60)

# Database file path
DATABASE = "postgresql://healthrecordsystem_user:PKoL65UbJ9pZTgdqM0KcVH0sooZGInYS@dpg-d5o4fvi4d50c73c1uc80-a.singapore-postgres.render.com/healthrecordsystem"
DOCUMENTS_DIR = os.path.join(PROJECT_ROOT, 'documents')
PROFILE_PICS_DIR = os.path.join(PROJECT_ROOT, 'static', 'profile_pics')

# Ensure directories exist
os.makedirs(DOCUMENTS_DIR, exist_ok=True)
os.makedirs(PROFILE_PICS_DIR, exist_ok=True)

# File upload configuration
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png', 'gif', 'doc', 'docx', 'xlsx', 'xls'}
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Initialize encryption for sensitive data
try:
    encryption_handler = get_encryption_handler()
except Exception as e:
    print(f"Warning: Could not initialize encryption: {e}")
    encryption_handler = None

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------------- USER ROLES ---------------------- #
ROLES = {
    'pending': 'Pending Approval',
    'super_admin': 'Super Administrator',
    'health_officer': 'Health Officer',
    'class_advisor': 'Class Advisor',
    'teacher_view_only': 'Teacher (View Only)'
}

# ---------------------- CONTEXT PROCESSORS ---------------------- #

@app.before_request
def check_user_status():
    """Check if logged-in user's account is still active and handle pending role"""
    if session.get("logged_in"):
        # Allow access to login, logout, register, and pending approval routes, and static files
        if request.endpoint in ['login', 'logout', 'register', 'pending_approval', 'static']:
            return
        
        # Redirect pending users to approval page
        if session.get("role") == "pending":
            return redirect(url_for("pending_approval"))
        
        db = get_db_connection()
        if db:
            try:
                cursor = db.cursor()
                cursor.execute("SELECT is_active FROM users WHERE id = ?", (session.get("user_id"),))
                user = cursor.fetchone()
                db.close()
                
                if not user or not safe_row_get(user, 'is_active', 1):
                    # User account has been deactivated
                    session.clear()
                    flash("Your account has been disabled. Please contact the administrator.", "danger")
                    return redirect(url_for("login"))
            except sqlite3.Error:
                db.close()

@app.context_processor
def inject_user():
    """Make current user available to all templates"""
    user = None
    if session.get("logged_in"):
        db = get_db_connection()
        if db:
            try:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (session.get("user_id"),))
                user = cursor.fetchone()
                db.close()
            except sqlite3.Error:
                pass
    return {'current_user': user, 'max': max, 'min': min, 'range': range}

# ---------------------- DATABASE HELPER FUNCTIONS ---------------------- #

def get_db_connection():
    """Get database connection with error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

def ensure_profile_pic_column():
    """Ensure profile_pic column exists in users table"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if profile_pic column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'profile_pic' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")
            conn.commit()
            print("Added profile_pic column to users table")
        
        if 'updated_at' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP")
            conn.commit()
            print("Added updated_at column to users table")
        
        conn.close()
    except sqlite3.Error as e:
        print(f"Migration error: {e}")

def ensure_strand_column():
    """Ensure strand column exists in students table"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if strand column exists
        cursor.execute("PRAGMA table_info(students)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'strand' not in columns:
            cursor.execute("ALTER TABLE students ADD COLUMN strand TEXT")
            conn.commit()
            print("Added strand column to students table")
        
        conn.close()
    except sqlite3.Error as e:
        print(f"Migration error: {e}")

def safe_row_get(row, key, default=None):
    """Safely get a value from a sqlite3.Row object"""
    if row is None:
        return default
    try:
        return row[key]
    except (IndexError, KeyError):
        return default

def decrypt_student_record(student):
    """Decrypt sensitive fields in a student record"""
    if not student or not encryption_handler:
        return student
    
    try:
        decrypted = dict(student)
        sensitive_fields = ['allergies', 'conditions', 'pastIllnesses', 'parentContact', 'emergencyContact', 'address', 'strand']
        for field in sensitive_fields:
            if field in decrypted and decrypted[field]:
                try:
                    decrypted[field] = encryption_handler.decrypt(decrypted[field])
                except:
                    # If decryption fails, leave as is (might already be plain text)
                    pass
        return decrypted
    except Exception as e:
        print(f"Error decrypting student record: {e}")
        return student

def decrypt_teacher_record(teacher):
    """Decrypt sensitive fields in a teacher record"""
    if not teacher or not encryption_handler:
        return teacher
    
    try:
        decrypted = dict(teacher)
        sensitive_fields = ['allergies', 'conditions', 'pastIllnesses', 'contact', 'address']
        for field in sensitive_fields:
            if field in decrypted and decrypted[field]:
                try:
                    decrypted[field] = encryption_handler.decrypt(decrypted[field])
                except:
                    # If decryption fails, leave as is (might already be plain text)
                    pass
        return decrypted
    except Exception as e:
        print(f"Error decrypting teacher record: {e}")
        return teacher

def decrypt_clinic_visit_record(visit):
    """Decrypt sensitive fields in a clinic visit record"""
    if not visit or not encryption_handler:
        return visit
    
    try:
        decrypted = dict(visit)
        sensitive_fields = ['diagnosis', 'assessment', 'physical_examination', 'medications_given', 'recommendations']
        for field in sensitive_fields:
            if field in decrypted and decrypted[field]:
                try:
                    decrypted[field] = encryption_handler.decrypt(decrypted[field])
                except:
                    # If decryption fails, leave as is (might already be plain text)
                    pass
        return decrypted
    except Exception as e:
        print(f"Error decrypting clinic visit record: {e}")
        return visit

def hash_password(password):
    """Hash password using bcrypt with salt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# ---------------------- AUTHENTICATION HELPERS ---------------------- #

def validate_password(password, confirm_password=None):
    """
    Validate password requirements.
    Returns: (is_valid: bool, message: str)
    """
    if not password:
        return False, "Password is required."
    
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    
    if confirm_password is not None and password != confirm_password:
        return False, "Passwords do not match."
    
    return True, ""

def validate_user_input(fullname, username, email, password, confirm_password=None):
    """
    Validate required user registration fields.
    Returns: (is_valid: bool, message: str)
    """
    if not all([fullname, username, email, password]):
        return False, "All fields are required."
    
    return validate_password(password, confirm_password)

def username_exists(username, exclude_user_id=None):
    """Check if username already exists in database"""
    db = get_db_connection()
    if not db:
        return None  # Error
    
    try:
        cursor = db.cursor()
        if exclude_user_id:
            cursor.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, exclude_user_id))
        else:
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        exists = cursor.fetchone() is not None
        db.close()
        return exists
    except sqlite3.Error:
        if db:
            db.close()
        return None  # Error

def create_user_in_db(username, password, fullname, email, role='pending', is_active=1, advisory_class=None):
    """
    Create a new user in the database.
    Returns: (success: bool, user_id: int or None, message: str)
    """
    db = get_db_connection()
    if not db:
        return False, None, "Database connection error"
    
    try:
        cursor = db.cursor()
        hashed_password = hash_password(password)
        cursor.execute("""
            INSERT INTO users (username, password, fullname, email, role, is_active, advisory_class)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, hashed_password, fullname, email, role, is_active, advisory_class))
        
        db.commit()
        user_id = cursor.lastrowid
        db.close()
        
        return True, user_id, "User created successfully"
    except sqlite3.Error as e:
        if db:
            db.close()
        return False, None, str(e)

def authenticate_user(username, password):
    """
    Authenticate user with username and password.
    Returns: (success: bool, user: dict or None)
    """
    if not username or not password:
        return False, None
    
    db = get_db_connection()
    if not db:
        return False, None
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()
        
        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            return True, user
        return False, None
    except sqlite3.Error:
        if db:
            db.close()
        return False, None

# Run database migrations on app start
ensure_profile_pic_column()
ensure_strand_column()

# ---------------------- AUDIT LOGGING ---------------------- #

def log_audit(action, table_name, record_id=None, old_values=None, new_values=None):
    """Log user action to audit log"""
    if not session.get("logged_in"):
        return
    
    db = get_db_connection()
    if not db:
        return
    
    try:
        cursor = db.cursor()
        user_id = session.get("user_id")
        username = session.get("username", "unknown")
        ip_address = request.remote_addr if request else None
        
        cursor.execute("""
            INSERT INTO audit_log (user_id, username, action, table_name, record_id, old_values, new_values, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, action, table_name, record_id, 
              json.dumps(old_values) if old_values else None,
              json.dumps(new_values) if new_values else None,
              ip_address))
        
        db.commit()
    except sqlite3.Error as e:
        print(f"Audit logging error: {e}")
    finally:
        db.close()

# ---------------------- ROLE-BASED ACCESS CONTROL ---------------------- #

def require_role(*allowed_roles):
    """Decorator to check user role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                flash("Please login first.", "warning")
                return redirect(url_for("login"))
            
            db = get_db_connection()
            if not db:
                flash("Database error.", "danger")
                return redirect(url_for("dashboard"))
            
            try:
                cursor = db.cursor()
                cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
                user = cursor.fetchone()
                db.close()
                
                if not user or safe_row_get(user, 'role') not in allowed_roles:
                    flash("You don't have permission to access this page.", "danger")
                    return redirect(url_for("dashboard"))
                
                return f(*args, **kwargs)
            except sqlite3.Error:
                flash("Database error.", "danger")
                return redirect(url_for("dashboard"))
        
        return decorated_function
    return decorator

def require_login(f):
    """Decorator to require login (no specific role required)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def get_advisor_class_filter():
    """Get SQL WHERE clause to filter records by advisor's class"""
    if not session.get("logged_in"):
        return ""
    
    db = get_db_connection()
    if not db:
        return ""
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        # Admins see all records
        if not user or safe_row_get(user, 'role') in ['super_admin', 'health_officer']:
            return ""
        
        # Class advisors see only their class
        if safe_row_get(user, 'role') == 'class_advisor' and safe_row_get(user, 'advisory_class'):
            return f"AND class = '{safe_row_get(user, 'advisory_class')}'"
        
        return ""
    except sqlite3.Error:
        return ""

# ---------------------- EMAIL HELPER FUNCTIONS ---------------------- #

def send_password_reset_email(recipient_email, user_fullname, reset_code):
    """Send password reset code via email"""
    try:
        # Check if email credentials are configured
        mail_username = app.config.get('MAIL_USERNAME', '')
        mail_password = app.config.get('MAIL_PASSWORD', '')
        mail_server = app.config.get('MAIL_SERVER', '')
        
        # DEVELOPMENT MODE: Skip email sending if you have network/firewall issues
        # Set SKIP_EMAIL_SENDING=True in environment to disable email
        if os.environ.get('SKIP_EMAIL_SENDING', 'False').lower() == 'true':
            print(f"[DEV MODE] Email skipped. Reset code for {recipient_email}: {reset_code}")
            return True, "Reset code generated (email disabled in development mode)"
        
        if not mail_username or not mail_password or not mail_server:
            # Email credentials not configured - return success to allow user to proceed
            print("Warning: Email credentials not configured. Skipping email send.")
            return True, "Reset code generated (email sending not configured)"
        
        subject = "Password Reset Code - LYFJSHS Health Record System"
        
        # Email body
        body = f"""
Hello {user_fullname},

You have requested to reset your password for the LYFJSHS Health Record Management System.

Your password reset code is: {reset_code}

This code will expire in 15 minutes. If you did not request this, please ignore this email.

Please do not share this code with anyone.

---
LYFJSHS Health Record Management System
Luis Y. Ferrer Jr. Senior High School
"""
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .content {{ padding: 20px; background: #f9f9f9; }}
        .code-box {{ background: #fff; border: 2px solid #667eea; padding: 15px; text-align: center; margin: 20px 0; border-radius: 5px; }}
        .code {{ font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 3px; }}
        .footer {{ text-align: center; font-size: 12px; color: #999; padding-top: 20px; border-top: 1px solid #ddd; }}
        .warning {{ color: #dc3545; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Password Reset Request</h2>
        </div>
        
        <div class="content">
            <p>Hello {user_fullname},</p>
            
            <p>You have requested to reset your password for the <strong>LYFJSHS Health Record Management System</strong>.</p>
            
            <p>Your password reset code is:</p>
            
            <div class="code-box">
                <div class="code">{reset_code}</div>
            </div>
            
            <p><span class="warning"> Important:</span></p>
            <ul>
                <li>This code will <strong>expire in 15 minutes</strong></li>
                <li>Do <strong>not</strong> share this code with anyone</li>
                <li>If you did not request this, please ignore this email</li>
            </ul>
            
            <p>For security, never share your reset code with anyone, including school staff.</p>
        </div>
        
        <div class="footer">
            <p>LYFJSHS Health Record Management System<br>Luis Y. Ferrer Jr. Senior High School</p>
            <p>© 2026 All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Create message
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=body,
            html=html_body
        )
        
        # Send email
        mail.send(msg)
        return True, "Email sent successfully"
    
    except Exception as e:
        error_str = str(e)
        print(f"Error sending email: {e}")
        
        # Provide helpful error message for common issues
        if "535" in error_str or "Username and Password not accepted" in error_str:
            return False, "Gmail authentication failed. Please use an App Password, not your regular Gmail password. Visit: https://myaccount.google.com/apppasswords"
        elif "getaddrinfo" in error_str or "nodename nor servname provided" in error_str:
            return False, "Could not connect to mail server. Your firewall may be blocking SMTP port 587. For testing, set environment variable: SKIP_EMAIL_SENDING=True"
        else:
            return False, f"Failed to send email: {error_str}"

# ---------------------- AUTH / LOGIN ---------------------- #

@app.route("/register", methods=["GET", "POST"])
def register():
    """Public user registration (creates pending users awaiting role assignment)"""
    if request.method == "POST":
        # Get and sanitize form inputs
        fullname = request.form.get("fullname", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        advisory_class = request.form.get("advisory_class", "").strip()
        
        # Validate input
        is_valid, message = validate_user_input(fullname, username, email, password, confirm_password)
        if not is_valid:
            flash(message, "danger")
            return render_template("auth/register.html")
        
        # Check if username exists
        username_check = username_exists(username)
        if username_check is None:
            flash("Database connection error. Please try again later.", "danger")
            return render_template("auth/register.html")
        elif username_check:
            flash("Username already exists. Please choose another.", "danger")
            return render_template("auth/register.html")
        
        # Create user with pending role
        success, user_id, message = create_user_in_db(username, password, fullname, email, role='pending', advisory_class=advisory_class)
        if not success:
            flash(f"Registration failed: {message}", "danger")
            return render_template("auth/register.html")
        
        flash("Registration successful! You can now login. Awaiting admin to assign your role.", "success")
        return redirect(url_for("login"))
    
    return render_template("auth/register.html")

@app.route("/api/users", methods=["POST"])
def create_user_api():
    """Create a new user via API (admin only - allows role assignment on creation)"""
    # Check authentication
    if not session.get("logged_in"):
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    # Check authorization
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            return jsonify({'success': False, 'message': 'Only super admin can create users'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    # Get request data
    data = request.get_json()
    fullname = data.get("fullname", "").strip()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "health_officer").strip()
    
    # Validate input
    if not all([fullname, username, email, password]):
        return jsonify({'success': False, 'message': 'All required fields must be provided'}), 400
    
    is_valid, message = validate_password(password)
    if not is_valid:
        return jsonify({'success': False, 'message': message}), 400
    
    if role not in ROLES:
        return jsonify({'success': False, 'message': 'Invalid role specified'}), 400
    
    # Check if username exists
    username_check = username_exists(username)
    if username_check is None:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
    elif username_check:
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    # Create user with specified role
    success, user_id, message = create_user_in_db(username, password, fullname, email, role=role, is_active=1)
    if not success:
        return jsonify({'success': False, 'message': f'Failed to create user: {message}'}), 500
    
    # Log action
    log_audit("CREATE", "users", user_id, {}, 
             {'username': username, 'role': role})
    
    return jsonify({'success': True, 'message': 'User created successfully', 'user_id': user_id}), 201

@app.route("/login", methods=["GET", "POST"])
def login():
    """User login with credentials validation and session setup"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("auth/index.html")
        
        # Authenticate user
        is_authentic, user = authenticate_user(username, password)
        if not is_authentic:
            flash("Invalid username or password.", "danger")
            return render_template("auth/index.html")
        
        # Check if account is active
        is_active = safe_row_get(user, 'is_active', 1)
        if not is_active:
            flash("Your account has been disabled. Please contact the administrator.", "danger")
            return render_template("auth/index.html")
        
        # Set session variables
        session["logged_in"] = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = safe_row_get(user, "role", "health_officer")
        
        # Log successful login
        log_audit("LOGIN", "users", user["id"])
        flash(f"Welcome back, {user['fullname']}!", "success")
        
        # Redirect pending users to approval page
        if session["role"] == "pending":
            return redirect(url_for("pending_approval"))
        
        return redirect(url_for("dashboard"))
    
    return render_template("auth/index.html")

@app.route("/logout")
def logout():
    """Clear session and log user out"""
    user_id = session.get("user_id")
    session.clear()
    
    if user_id:
        log_audit("LOGOUT", "users", user_id)
    
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("login"))

# ---------------------- FORGOT PASSWORD ---------------------- #

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Handle forgot password request - user enters email"""

    # Simple rate limiting: max 5 attempts per hour per IP
    from datetime import datetime, timedelta
    client_ip = request.remote_addr or "unknown"
    rate_limit_key = f"pwd_reset_{client_ip}"

    current_time = datetime.now()
    attempts = session.get(rate_limit_key, [])
    # Clean old attempts (older than 1 hour) - convert to timestamps to avoid timezone issues
    attempts = [t for t in attempts if isinstance(t, (int, float)) and t > current_time.timestamp() - 3600]

    if len(attempts) >= 5:
        flash("Too many password reset attempts. Please try again in an hour.", "danger")
        return render_template("auth/forgot_password.html")

    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            flash("Please enter your email address.", "danger")
            return render_template("auth/forgot_password.html")

        # Validate email format
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash("Please enter a valid email address.", "danger")
            return render_template("auth/forgot_password.html")

        db = get_db_connection()
        if not db:
            flash("Database connection error. Please try again later.", "danger")
            return render_template("auth/forgot_password.html")

        try:
            cursor = db.cursor()

            # Clean up expired tokens periodically (every 10th request)
            import random
            if random.randint(1, 10) == 1:
                # Convert current_time to string format for SQL comparison
                current_time_str = current_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                cursor.execute("DELETE FROM password_reset_tokens WHERE expires_at < ?", (current_time_str,))

            # Check if email exists in users table
            cursor.execute("SELECT id, fullname FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            if not user:
                # Don't reveal if email exists or not for security
                # Still record the attempt for rate limiting (use timestamp to avoid timezone issues)
                attempts.append(current_time.timestamp())
                session[rate_limit_key] = attempts
                flash("If that email address is associated with an account, you will receive a reset code.", "success")
                db.close()
                return redirect(url_for("login"))

            user_id = user['id']
            user_fullname = user['fullname']

            # Record the attempt (use timestamp to avoid timezone issues)
            attempts.append(current_time.timestamp())
            session[rate_limit_key] = attempts

            # Generate reset code (6-digit code)
            reset_code = ''.join(random.choices(string.digits, k=6))

            # Clear any existing reset tokens for this user
            cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = ? AND is_used = 0", (user_id,))

            # Create new reset token (expires in 15 minutes)
            expires_at = datetime.now() + timedelta(minutes=15)

            cursor.execute("""
                INSERT INTO password_reset_tokens (user_id, email, reset_code, expires_at)
                VALUES (?, ?, ?, ?)
            """, (user_id, email, reset_code, expires_at))

            db.commit()
            db.close()

            # Send reset code via email
            email_sent, email_message = send_password_reset_email(email, user_fullname, reset_code)

            if email_sent:
                flash(f"Reset code has been sent to {email}. Please check your email.", "success")
            else:
                flash(f"Account found, but could not send email: {email_message}. Please try again later.", "warning")

            # Redirect to verify code page
            return redirect(url_for("verify_reset_code", email=email))

        except sqlite3.Error as e:
            flash(f"An error occurred while processing your request. Please try again.", "danger")
            if db:
                db.close()
            return render_template("auth/forgot_password.html")

    return render_template("auth/forgot_password.html")

@app.route("/verify-reset-code", methods=["GET", "POST"])
def verify_reset_code():
    """Verify the reset code sent to email"""
    email = request.args.get("email", "").strip()

    # Validate email parameter for GET requests
    if request.method == "GET" and not email:
        flash("Email address is required. Please request a new password reset.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        reset_code = request.form.get("reset_code", "").strip()

        if not email or not reset_code:
            flash("Please enter both email and reset code.", "danger")
            return render_template("auth/verify_reset_code.html", email=email)

        # Validate email format
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash("Invalid email format. Please check your email address.", "danger")
            return render_template("auth/verify_reset_code.html", email=email)

        db = get_db_connection()
        if not db:
            flash("Database connection error. Please try again later.", "danger")
            return render_template("auth/verify_reset_code.html", email=email)

        try:
            cursor = db.cursor()

            # Verify the reset code
            # SQLite stores TIMESTAMP as string in format: "2026-01-10 16:59:22.863883"
            from datetime import datetime, timedelta
            current_time_dt = datetime.now()
            current_time_str = current_time_dt.strftime('%Y-%m-%d %H:%M:%S.%f')

            cursor.execute("""
                SELECT prt.id, prt.user_id, prt.expires_at FROM password_reset_tokens prt
                WHERE prt.email = ? AND prt.reset_code = ? AND prt.is_used = 0
                AND prt.expires_at > ?
            """, (email, reset_code, current_time_str))

            result = cursor.fetchone()

            if not result:
                # Check if there are any valid tokens for this email to provide better feedback
                cursor.execute("""
                    SELECT COUNT(*) as token_count FROM password_reset_tokens
                    WHERE email = ? AND is_used = 0 AND expires_at > ?
                """, (email, current_time_str))
                token_check = cursor.fetchone()

                if token_check and token_check['token_count'] > 0:
                    flash("Invalid reset code. Please check the code and try again.", "danger")
                else:
                    flash("No valid reset codes found for this email. Please request a new password reset.", "danger")

                db.close()
                return render_template("auth/verify_reset_code.html", email=email)

            token_id = result['id']
            user_id = result['user_id']
            expires_at_str = result['expires_at']

            # Convert expires_at from string to datetime
            expires_at = datetime.fromisoformat(expires_at_str)

            # Check if token is about to expire
            if expires_at < current_time_dt + timedelta(minutes=5):
                flash("Warning: This reset code will expire soon. Please complete the password reset quickly.", "warning")

            db.close()

            # Store in session for recovery if URL parameters are lost
            session['password_reset_token_id'] = token_id
            session['password_reset_email'] = email

            # Redirect to reset password page with token and user info
            # Convert token_id to string for URL parameter
            return redirect(url_for("reset_password", token_id=str(token_id), email=email))

        except sqlite3.Error as e:
            flash(f"An error occurred while verifying your code. Please try again.", "danger")
            if db:
                db.close()
            return render_template("auth/verify_reset_code.html", email=email)

    return render_template("auth/verify_reset_code.html", email=email)

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Reset password after code verification"""
    # Try to get from URL parameters first, then from session as fallback
    token_id = request.args.get("token_id", "").strip() or session.get("password_reset_token_id", "")
    email = request.args.get("email", "").strip() or session.get("password_reset_email", "")

    # Enhanced validation for production
    if not token_id or not email:
        flash("This password reset link is invalid or has expired. Please request a new password reset.", "danger")
        # Clear invalid session data
        session.pop("password_reset_token_id", None)
        session.pop("password_reset_email", None)
        return redirect(url_for("forgot_password"))

    # Validate email format
    import re
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        flash("Invalid email format. Please request a new password reset.", "danger")
        return redirect(url_for("forgot_password"))

    # Check if token_id is numeric and convert to int immediately
    try:
        token_id_int = int(token_id)
    except (ValueError, TypeError):
        flash("Invalid reset link. Please request a new password reset.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        token_id_str = request.form.get("token_id", "").strip()
        email = request.form.get("email", "").strip()

        # Validate and convert token_id to integer
        try:
            token_id = int(token_id_str)
        except (ValueError, TypeError):
            flash("Invalid reset token. Please request a new password reset.", "danger")
            return redirect(url_for("forgot_password"))

        # Validate password
        if not new_password or not confirm_password:
            flash("Please enter and confirm your new password.", "danger")
            return render_template("auth/reset_password.html", token_id=token_id, email=email)

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("auth/reset_password.html", token_id=token_id, email=email)

        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("auth/reset_password.html", token_id=token_id, email=email)

        db = get_db_connection()
        if not db:
            flash("Database connection error. Please try again later.", "danger")
            return render_template("auth/reset_password.html", token_id=token_id, email=email)

        try:
            cursor = db.cursor()

            # Verify the token still exists and is valid
            # SQLite stores TIMESTAMP as string in format: "2026-01-10 16:59:22.863883"
            from datetime import datetime, timedelta
            current_time_dt = datetime.now()
            current_time_str = current_time_dt.strftime('%Y-%m-%d %H:%M:%S.%f')

            cursor.execute("""
                SELECT user_id, expires_at FROM password_reset_tokens
                WHERE id = ? AND email = ? AND is_used = 0 AND expires_at > ?
            """, (token_id, email, current_time_str))

            result = cursor.fetchone()

            if not result:
                flash("This password reset link has expired or has already been used. Please request a new password reset.", "danger")
                db.close()
                return redirect(url_for("forgot_password"))

            user_id = result['user_id']
            expires_at_str = result['expires_at']

            # Convert expires_at from string to datetime
            expires_at = datetime.fromisoformat(expires_at_str)

            # Check if token is about to expire (within 5 minutes)
            if expires_at < current_time_dt + timedelta(minutes=5):
                flash("This password reset link will expire soon. Please complete the reset quickly.", "warning")

            # Hash new password
            hashed_password = hash_password(new_password)

            # Update user password
            cursor.execute("""
                UPDATE users SET password = ? WHERE id = ?
            """, (hashed_password, user_id))

            # Mark token as used
            cursor.execute("""
                UPDATE password_reset_tokens SET is_used = 1 WHERE id = ?
            """, (token_id,))

            db.commit()
            db.close()

            # Clear session after successful reset
            session.pop("password_reset_token_id", None)
            session.pop("password_reset_email", None)

            # Log the password reset
            log_audit("PASSWORD_RESET", "users", user_id)

            flash("Your password has been reset successfully. Please login with your new password.", "success")
            return redirect(url_for("login"))

        except sqlite3.Error as e:
            flash(f"An error occurred while resetting your password. Please try again.", "danger")
            if db:
                db.close()
            return render_template("auth/reset_password.html", token_id=token_id, email=email)

    return render_template("auth/reset_password.html", token_id=token_id, email=email)

@app.route("/profile-settings", methods=["GET", "POST"])
def profile_settings():
    """User profile customization page"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("dashboard"))
    
    user_id = session.get("user_id")
    cursor = db.cursor()
    
    if request.method == "POST":
        try:
            # Get form data
            fullname = request.form.get("fullname", "").strip()
            email = request.form.get("email", "").strip()
            
            # Validate inputs
            if not fullname:
                flash("Full name is required.", "danger")
                db.close()
                return redirect(url_for("profile_settings"))
            
            if not email:
                flash("Email is required.", "danger")
                db.close()
                return redirect(url_for("profile_settings"))
            
            # Check if email already exists (for other users)
            cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user_id))
            if cursor.fetchone():
                flash("Email already in use by another account.", "danger")
                db.close()
                return redirect(url_for("profile_settings"))
            
            # Handle profile picture upload
            profile_pic = None
            if "profile_pic" in request.files and request.files["profile_pic"].filename:
                file = request.files["profile_pic"]
                
                # Validate file
                if '.' not in file.filename:
                    flash("File must have an extension.", "danger")
                    db.close()
                    return redirect(url_for("profile_settings"))
                
                ext = file.filename.rsplit('.', 1)[1].lower()
                if ext not in ALLOWED_IMAGE_EXTENSIONS:
                    flash(f"Only image files (jpg, jpeg, png, gif) are allowed.", "danger")
                    db.close()
                    return redirect(url_for("profile_settings"))
                
                try:
                    # Delete old profile picture if exists
                    cursor.execute("SELECT profile_pic FROM users WHERE id = ?", (user_id,))
                    old_result = cursor.fetchone()
                    if old_result and old_result[0]:
                        old_pic_path = os.path.join(PROFILE_PICS_DIR, old_result[0])
                        if os.path.exists(old_pic_path):
                            try:
                                os.remove(old_pic_path)
                            except Exception as e:
                                print(f"Could not delete old picture: {e}")
                    
                    # Save new profile picture
                    filename = f"profile_{user_id}.{ext}"
                    filepath = os.path.join(PROFILE_PICS_DIR, filename)
                    file.save(filepath)
                    profile_pic = filename
                    
                except Exception as e:
                    flash(f"Error uploading picture: {str(e)}", "danger")
                    db.close()
                    return redirect(url_for("profile_settings"))
            
            # Update user profile in database
            if profile_pic:
                cursor.execute("""
                    UPDATE users 
                    SET fullname = ?, email = ?, profile_pic = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (fullname, email, profile_pic, user_id))
            else:
                cursor.execute("""
                    UPDATE users 
                    SET fullname = ?, email = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (fullname, email, user_id))
            
            db.commit()
            
            # Update session
            session["fullname"] = fullname
            
            flash("Profile updated successfully!", "success")
            db.close()
            return redirect(url_for("profile_settings"))
        
        except sqlite3.Error as e:
            db.rollback()
            db.close()
            flash(f"Database error: {str(e)}", "danger")
            return redirect(url_for("profile_settings"))
    
    # GET request - show profile form
    try:
        cursor.execute("SELECT id, username, fullname, email, profile_pic FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        db.close()
        
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("dashboard"))
        
        user_data = dict(zip(['id', 'username', 'fullname', 'email', 'profile_pic'], user))
        return render_template("profile_settings.html", user=user_data)
    
    except sqlite3.Error as e:
        db.close()
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/api/search-users")
def search_users():
    """Search users by name or username"""
    if not session.get("logged_in"):
        return jsonify({"error": "Not authenticated"}), 401
    
    query = request.args.get("q", "").strip()
    if not query or len(query) < 2:
        return jsonify({"results": []})
    
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, username, fullname FROM users 
            WHERE username LIKE ? OR fullname LIKE ?
            LIMIT 10
        """, (f"%{query}%", f"%{query}%"))
        
        results = []
        for user in cursor.fetchall():
            results.append({
                "id": user[0],
                "username": user[1],
                "fullname": user[2]
            })
        
        return jsonify({"results": results})
    
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/api/profile-picture")
def get_profile_picture():
    """Get current user's profile picture"""
    if not session.get("logged_in"):
        return jsonify({"error": "Not authenticated"}), 401
    
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT profile_pic FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        
        if user and user[0]:
            return jsonify({"profile_pic": user[0]})
        else:
            return jsonify({"profile_pic": None})
    
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/pending-approval")
def pending_approval():
    """Show page for users waiting for role assignment"""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("login"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT fullname, email, created_at, advisory_class FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("logout"))
        
        return render_template("auth/pending_approval.html", user=user)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("logout"))

# ---------------------- DASHBOARD ---------------------- #

@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("login"))
    
    try:
        cursor = db.cursor()
        
        # Get current user profile
        cursor.execute("SELECT * FROM users WHERE id = ?", (session.get("user_id"),))
        current_user = cursor.fetchone()
        
        # Check if user has a role assigned
        user_role = safe_row_get(current_user, 'role') if current_user else None
        if not user_role:
            db.close()
            flash("Your account is pending admin approval. Please wait for your role to be assigned.", "warning")
            return redirect(url_for("pending_approval"))
        
        # For class advisors, filter by their assigned class
        if current_user and safe_row_get(current_user, 'role') == 'class_advisor' and safe_row_get(current_user, 'advisory_class'):
            advisory_class = safe_row_get(current_user, 'advisory_class')
            
            # Get students from their class
            cursor.execute("SELECT * FROM students WHERE class = ?", (advisory_class,))
            students = cursor.fetchall()
            students = [decrypt_student_record(s) for s in students]
            total_students = len(students)
            total_records = len(
                [s for s in students if s["allergies"] or s["conditions"]]
            )
            
            # Get recent students from their class (last 5 added)
            cursor.execute("""
                SELECT id, studentLRN, name, class, dob 
                FROM students 
                WHERE class = ?
                ORDER BY id DESC 
                LIMIT 5
            """, (advisory_class,))
            recent_students = cursor.fetchall()
            recent_students = [decrypt_student_record(s) for s in recent_students]
            
            # Class advisors don't see teacher data
            teachers = []
            total_teachers = 0
            total_teacher_records = 0
            recent_teachers = []
        else:
            # Admins see all students
            # Get students
            cursor.execute("SELECT * FROM students")
            students = cursor.fetchall()
            students = [decrypt_student_record(s) for s in students]
            total_students = len(students)
            total_records = len(
                [s for s in students if s["allergies"] or s["conditions"]]
            )
            
            # Get recent students (last 5 added)
            cursor.execute("""
                SELECT id, studentLRN, name, class, dob 
                FROM students 
                ORDER BY id DESC 
                LIMIT 5
            """)
            recent_students = cursor.fetchall()
            recent_students = [decrypt_student_record(s) for s in recent_students]
        
        # Get teachers
        cursor.execute("SELECT * FROM teachers")
        teachers = cursor.fetchall()
        teachers = [decrypt_teacher_record(t) for t in teachers]
        total_teachers = len(teachers)
        total_teacher_records = len(
            [t for t in teachers if t["allergies"] or t["conditions"]]
        )
        
        # Get recent teachers (last 5 added)
        cursor.execute("""
            SELECT id, teacherID, name, department, dob 
            FROM teachers 
            ORDER BY id DESC 
            LIMIT 5
        """)
        recent_teachers = cursor.fetchall()
        recent_teachers = [decrypt_teacher_record(t) for t in recent_teachers]
        
        # Get blood type distribution
        cursor.execute("SELECT blood, COUNT(*) as count FROM students WHERE blood IS NOT NULL AND blood != '' GROUP BY blood")
        blood_dist = cursor.fetchall()
        blood_distribution = {row['blood']: row['count'] for row in blood_dist} if blood_dist else {}
        
        # Get vaccination status
        cursor.execute("SELECT vaccination, COUNT(*) as count FROM students WHERE vaccination IS NOT NULL AND vaccination != '' GROUP BY vaccination")
        vacc_status = cursor.fetchall()
        vaccination_status = {row['vaccination']: row['count'] for row in vacc_status} if vacc_status else {}
        
        # REFACTORED: Student Analytics
        # 1. Get total students with allergies per strand
        cursor.execute("""
            SELECT id, strand, allergies
            FROM students 
            WHERE allergies IS NOT NULL AND allergies != '' AND strand IS NOT NULL AND strand != ''
        """)
        allergies_records = cursor.fetchall()
        # Decrypt and build strand allergies data
        students_allergies_strand = {}
        for record in allergies_records:
            try:
                # Decrypt strand and allergies
                decrypted_record = dict(record)
                if encryption_handler:
                    try:
                        decrypted_record['strand'] = encryption_handler.decrypt(decrypted_record['strand'])
                    except:
                        pass
                strand = decrypted_record['strand']
                if strand:
                    students_allergies_strand[strand] = students_allergies_strand.get(strand, 0) + 1
            except Exception as e:
                print(f"Error processing allergy record: {e}")
        
        # 2. Get strands with most clinic visits records
        cursor.execute("""
            SELECT s.id, s.strand, COUNT(cv.id) as visit_count 
            FROM students s
            LEFT JOIN clinic_visits cv ON s.id = cv.person_id AND cv.person_type = 'student'
            WHERE s.strand IS NOT NULL AND s.strand != ''
            GROUP BY s.id, s.strand
        """)
        clinic_visits_records = cursor.fetchall()
        # Decrypt and aggregate by strand
        strands_most_visits = {}
        for record in clinic_visits_records:
            try:
                decrypted_record = dict(record)
                if encryption_handler:
                    try:
                        decrypted_record['strand'] = encryption_handler.decrypt(decrypted_record['strand'])
                    except:
                        pass
                strand = decrypted_record['strand']
                visit_count = decrypted_record['visit_count']
                if strand:
                    strands_most_visits[strand] = strands_most_visits.get(strand, 0) + visit_count
            except Exception as e:
                print(f"Error processing clinic visit record: {e}")
        
        # REFACTORED: Teacher Analytics
        # 1. Get total teachers with allergies
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM teachers 
            WHERE allergies IS NOT NULL AND allergies != ''
        """)
        teachers_with_allergies = cursor.fetchone()
        total_teachers_allergies = teachers_with_allergies['count'] if teachers_with_allergies else 0
        
        # 2. Get most clinic visits records by teachers
        cursor.execute("""
            SELECT t.id, t.name, COUNT(cv.id) as visit_count 
            FROM teachers t
            LEFT JOIN clinic_visits cv ON t.id = cv.person_id AND cv.person_type = 'teacher'
            GROUP BY t.id
            ORDER BY visit_count DESC
            LIMIT 10
        """)
        teachers_clinic_visits = cursor.fetchall()
        # Decrypt teacher names and aggregate
        teachers_most_visits = {}
        for record in teachers_clinic_visits:
            try:
                decrypted_record = dict(record)
                if encryption_handler:
                    try:
                        decrypted_record['name'] = encryption_handler.decrypt(decrypted_record['name'])
                    except:
                        pass
                teacher_name = decrypted_record['name']
                visit_count = decrypted_record['visit_count']
                if teacher_name:
                    teachers_most_visits[teacher_name] = visit_count
            except Exception as e:
                print(f"Error processing teacher record: {e}")
        
        # Get allergies (for compatibility)
        cursor.execute("""
            SELECT allergies, COUNT(*) as count 
            FROM students 
            WHERE allergies IS NOT NULL AND allergies != '' 
            GROUP BY allergies
            ORDER BY count DESC
            LIMIT 10
        """)
        allerg = cursor.fetchall()
        allergies = {row['allergies']: row['count'] for row in allerg} if allerg else {}
        
        # Get past illnesses (for compatibility)
        cursor.execute("""
            SELECT pastIllnesses, COUNT(*) as count 
            FROM students 
            WHERE pastIllnesses IS NOT NULL AND pastIllnesses != '' 
            GROUP BY pastIllnesses
            ORDER BY count DESC
            LIMIT 10
        """)
        ill = cursor.fetchall()

        illnesses = {row['pastIllnesses']: row['count'] for row in ill} if ill else {}
        
        # Get pre-existing conditions
        cursor.execute("""
            SELECT conditions, COUNT(*) as count 
            FROM students 
            WHERE conditions IS NOT NULL AND conditions != '' 
            GROUP BY conditions
            ORDER BY count DESC
            LIMIT 10
        """)
        cond = cursor.fetchall()
        conditions = {row['conditions']: row['count'] for row in cond} if cond else {}
        
        # Count pending vaccinations
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE vaccination = 'Pending'")
        pending_vacc = cursor.fetchone()
        pending_vaccinations = pending_vacc['count'] if pending_vacc else 0
        
        # Count students with allergies
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE allergies IS NOT NULL AND allergies != ''")
        allergy_students = cursor.fetchone()
        students_with_allergies = allergy_students['count'] if allergy_students else 0
        
        # Count expired items (using inventory table)
        cursor.execute("SELECT COUNT(*) as count FROM inventory WHERE expiry_date IS NOT NULL AND expiry_date < date('now')")
        expired = cursor.fetchone()
        expired_items = expired['count'] if expired else 0
        
        # Count expiring soon (30 days)
        cursor.execute("SELECT COUNT(*) as count FROM inventory WHERE expiry_date IS NOT NULL AND expiry_date BETWEEN date('now') AND date('now', '+30 days')")
        expiring = cursor.fetchone()
        expiring_soon = expiring['count'] if expiring else 0
        
        # Create summary object
        summary = {
            'total_students': total_students,
            'total_teachers': total_teachers,
            'pending_vaccinations': pending_vaccinations,
            'expired_items': expired_items,
            'expiring_soon': expiring_soon,
            'students_with_allergies': students_with_allergies
        }
        
        db.close()
        
        return render_template(
            "shared/dashboard.html",
            current_user=current_user,
            user_role=user_role,
            total_students=total_students,
            total_records=total_records,
            total_teachers=total_teachers,
            total_teacher_records=total_teacher_records,
            recent_students=recent_students,
            recent_teachers=recent_teachers,
            summary=summary,
            blood_distribution=blood_distribution,
            vaccination_status=vaccination_status,
            allergies=allergies,
            illnesses=illnesses,
            conditions=conditions,
            # Refactored Analytics
            students_allergies_strand=students_allergies_strand,
            strands_most_visits=strands_most_visits,
            total_teachers_allergies=total_teachers_allergies,
            teachers_most_visits=teachers_most_visits
        )
    except sqlite3.Error as e:
        flash(f"Error loading dashboard: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("login"))

# ---------------------- USER MANAGEMENT ---------------------- #

@app.route("/user-management")
def user_management():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("login"))
    
    try:
        cursor = db.cursor()
        
        # Get all students
        cursor.execute("SELECT * FROM students ORDER BY name")
        students = cursor.fetchall()
        students = [decrypt_student_record(s) for s in students]
        
        # Get all teachers
        cursor.execute("SELECT * FROM teachers ORDER BY name")
        teachers = cursor.fetchall()
        teachers = [decrypt_teacher_record(t) for t in teachers]
        
        db.close()
        
        # Pagination settings
        items_per_page = 7
        
        # Calculate pagination for students
        student_total = len(students)
        student_pages = (student_total + items_per_page - 1) // items_per_page if student_total > items_per_page else 1
        show_student_pagination = student_total > items_per_page
        
        # Calculate pagination for teachers
        teacher_total = len(teachers)
        teacher_pages = (teacher_total + items_per_page - 1) // items_per_page if teacher_total > items_per_page else 1
        show_teacher_pagination = teacher_total > items_per_page
        
        return render_template(
            "admin/user-management.html",
            students=students,
            teachers=teachers,
            items_per_page=items_per_page,
            student_total=student_total,
            student_pages=student_pages,
            show_student_pagination=show_student_pagination,
            teacher_total=teacher_total,
            teacher_pages=teacher_pages,
            show_teacher_pagination=show_teacher_pagination,
        )
    except sqlite3.Error as e:
        flash(f"Error loading user management: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("login"))

# ---------------------- RECORD LISTS ---------------------- #

@app.route("/record-lists")
def record_lists():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("login"))
    
    try:
        cursor = db.cursor()
        
        # Get user role and advisory class
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        user_role = safe_row_get(user, 'role') if user else None
        advisory_class = safe_row_get(user, 'advisory_class') if user else None
        
        # Class advisors can only see their own section students (by class), not teachers
        if user_role == 'class_advisor' and advisory_class:
            cursor.execute("SELECT * FROM students WHERE class = ? ORDER BY name", (advisory_class,))
            students = cursor.fetchall()
            students = [decrypt_student_record(s) for s in students]
            teachers = []  # Class advisors cannot see teachers
        else:
            # Admins see all students and teachers
            cursor.execute("SELECT * FROM students ORDER BY name")
            students = cursor.fetchall()
            students = [decrypt_student_record(s) for s in students]
            cursor.execute("SELECT * FROM teachers ORDER BY name")
            teachers = cursor.fetchall()
            teachers = [decrypt_teacher_record(t) for t in teachers]
        
        db.close()
        
        # Pagination settings
        items_per_page = 7
        
        # Calculate pagination for students
        student_total = len(students)
        student_pages = (student_total + items_per_page - 1) // items_per_page if student_total > items_per_page else 1
        show_student_pagination = student_total > items_per_page
        
        # Calculate pagination for teachers
        teacher_total = len(teachers)
        teacher_pages = (teacher_total + items_per_page - 1) // items_per_page if teacher_total > items_per_page else 1
        show_teacher_pagination = teacher_total > items_per_page
        
        return render_template(
            "records/record-lists.html",
            students=students,
            teachers=teachers,
            user_role=user_role,
            advisory_class=advisory_class,
            items_per_page=items_per_page,
            student_total=student_total,
            student_pages=student_pages,
            show_student_pagination=show_student_pagination,
            teacher_total=teacher_total,
            teacher_pages=teacher_pages,
            show_teacher_pagination=show_teacher_pagination,
        )
    except sqlite3.Error as e:
        flash(f"Error loading record lists: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("login"))

# ---------------------- ADD STUDENT ---------------------- #

@app.route("/add_student", methods=["GET", "POST"])
def add_student():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot add students
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to add students.", "danger")
            return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        student_data_raw = {
            'studentLRN': request.form.get("studentLRN", "").strip(),
            'name': request.form.get("name", "").strip(),
            'class': request.form.get("class", "").strip(),
            'strand': request.form.get("strand", "").strip() or None,
            'dob': request.form.get("dob") or None,
            'address': request.form.get("address", "").strip() or None,
            'parentContact': request.form.get("parentContact", "").strip() or None,
            'emergencyContact': request.form.get("emergencyContact", "").strip() or None,
            'height': request.form.get("height", "").strip() or None,
            'weight': request.form.get("weight", "").strip() or None,
            'blood': request.form.get("blood", "").strip() or None,
            'pastIllnesses': request.form.get("pastIllnesses", "").strip() or None,
            'allergies': request.form.get("allergies", "").strip() or None,
            'conditions': request.form.get("conditions", "").strip() or None,
            'vaccination': request.form.get("vaccination", "").strip() or None,
        }
        
        # Validate required fields
        if not student_data_raw['studentLRN'] or not student_data_raw['name'] or not student_data_raw['class']:
            flash("Student LRN, Name, and Class are required fields.", "danger")
            return redirect(url_for("user_management"))
        
        # Encrypt sensitive fields
        student_data = student_data_raw.copy()
        if encryption_handler:
            for field in ['allergies', 'conditions','pastIllnesses', 'parentContact', 'emergencyContact', 'address', 'strand']:
                if student_data[field]:
                    try:
                        student_data[field] = encryption_handler.encrypt(student_data[field])
                    except Exception as e:
                        print(f"Encryption error for field {field}: {e}")
                        flash(f"Warning: Could not encrypt {field}. Data saved unencrypted.", "warning")
        
        student_data_tuple = (
            student_data['studentLRN'],
            student_data['name'],
            student_data['class'],
            student_data['strand'],
            student_data['dob'],
            student_data['address'],
            student_data['parentContact'],
            student_data['emergencyContact'],
            student_data['height'],
            student_data['weight'],
            student_data['blood'],
            student_data['pastIllnesses'],
            student_data['allergies'],
            student_data['conditions'],
            student_data['vaccination'],
        )
        
        db = get_db_connection()
        if not db:
            flash("Database connection error.", "danger")
            return redirect(url_for("user_management"))
        
        try:
            cursor = db.cursor()
            
            # Check if LRN already exists
            cursor.execute("SELECT id FROM students WHERE studentLRN = ?", (student_data_raw['studentLRN'],))
            if cursor.fetchone():
                flash("Student with this LRN already exists.", "danger")
                db.close()
                return redirect(url_for("user_management"))
            
            cursor.execute("""
                INSERT INTO students (
                    studentLRN, name, class, strand, dob, address,
                    parentContact, emergencyContact,
                    height, weight, blood,
                    pastIllnesses, allergies, conditions, vaccination
                ) VALUES (?, ?, ?, ?, ?, ?,
                          ?, ?,
                          ?, ?, ?,
                          ?, ?, ?, ?)
            """, student_data_tuple)
            
            db.commit()
            
            # Log audit
            log_audit("ADD_STUDENT", "students", cursor.lastrowid, {}, student_data_raw)
            
            db.close()
            
            flash("Student added successfully!", "success")
            return redirect(url_for("user_management"))
            
        except sqlite3.Error as e:
            flash(f"Error adding student: {str(e)}", "danger")
            if db:
                db.close()
            return redirect(url_for("user_management"))
    
    return redirect(url_for("user_management"))

# ---------------------- STUDENT LIST ---------------------- #

@app.route("/students")
def student_list():
    return redirect(url_for("record_lists"))

# ---------------------- STUDENT HEALTH PROFILE ---------------------- #

@app.route("/student/<int:id>")
def student_health(id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return redirect(url_for("record_lists"))

# ---------------------- ADD TEACHER ---------------------- #

@app.route("/add_teacher", methods=["GET", "POST"])
def add_teacher():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot add teachers
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to add teachers.", "danger")
            return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        teacher_data_raw = {
            'teacherID': request.form.get("teacherID", "").strip(),
            'name': request.form.get("name", "").strip(),
            'department': request.form.get("department", "").strip(),
            'dob': request.form.get("dob") or None,
            'address': request.form.get("address", "").strip() or None,
            'contact': request.form.get("contact", "").strip() or None,
            'height': request.form.get("height", "").strip() or None,
            'weight': request.form.get("weight", "").strip() or None,
            'blood': request.form.get("blood", "").strip() or None,
            'pastIllnesses': request.form.get("pastIllnesses", "").strip() or None,
            'allergies': request.form.get("allergies", "").strip() or None,
            'conditions': request.form.get("conditions", "").strip() or None,
            'vaccination': request.form.get("vaccination", "").strip() or None,
        }
        
        # Validate required fields
        if not teacher_data_raw['teacherID'] or not teacher_data_raw['name'] or not teacher_data_raw['department']:
            flash("Teacher ID, Name, and Department are required fields.", "danger")
            return redirect(url_for("user_management"))
        
        # Encrypt sensitive fields
        teacher_data = teacher_data_raw.copy()
        if encryption_handler:
            for field in ['allergies', 'conditions', 'pastIllnesses', 'contact', 'address']:
                if teacher_data[field]:
                    try:
                        teacher_data[field] = encryption_handler.encrypt(teacher_data[field])
                    except Exception as e:
                        print(f"Encryption error for field {field}: {e}")
                        flash(f"Warning: Could not encrypt {field}. Data saved unencrypted.", "warning")
        
        teacher_data_tuple = (
            teacher_data['teacherID'],
            teacher_data['name'],
            teacher_data['department'],
            teacher_data['dob'],
            teacher_data['address'],
            teacher_data['contact'],
            teacher_data['height'],
            teacher_data['weight'],
            teacher_data['blood'],
            teacher_data['pastIllnesses'],
            teacher_data['allergies'],
            teacher_data['conditions'],
            teacher_data['vaccination'],
        )
        
        db = get_db_connection()
        if not db:
            flash("Database connection error.", "danger")
            return redirect(url_for("user_management"))
        
        try:
            cursor = db.cursor()
            
            # Check if Teacher ID already exists
            cursor.execute("SELECT id FROM teachers WHERE teacherID = ?", (teacher_data_raw['teacherID'],))
            if cursor.fetchone():
                flash("Teacher with this ID already exists.", "danger")
                db.close()
                return redirect(url_for("user_management"))
            
            cursor.execute("""
                INSERT INTO teachers (
                    teacherID, name, department, dob, address,
                    contact, height, weight, blood,
                    pastIllnesses, allergies, conditions, vaccination
                ) VALUES (?, ?, ?, ?, ?,
                          ?, ?, ?, ?,
                          ?, ?, ?, ?)
            """, teacher_data_tuple)
            
            db.commit()
            
            # Log audit
            log_audit("ADD_TEACHER", "teachers", cursor.lastrowid, {}, teacher_data_raw)
            
            db.close()
            
            flash("Teacher added successfully!", "success")
            return redirect(url_for("user_management"))
            
        except sqlite3.Error as e:
            flash(f"Error adding teacher: {str(e)}", "danger")
            if db:
                db.close()
            return redirect(url_for("user_management"))
    
    return redirect(url_for("user_management"))

# ---------------------- TEACHER LIST ---------------------- #

@app.route("/teachers")
def teacher_list():
    return redirect(url_for("record_lists"))

# ---------------------- TEACHER HEALTH PROFILE ---------------------- #

@app.route("/teacher/<int:id>")
def teacher_health(id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return redirect(url_for("record_lists"))

# ---------------------- DELETE STUDENT ---------------------- #

@app.route("/delete_student/<int:id>", methods=["POST"])
def delete_student(id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot delete students
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to delete students.", "danger")
            db.close()
            return redirect(url_for("dashboard"))
        db.close()
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("student_list"))
    
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM students WHERE id = ?", (id,))
        db.commit()
        db.close()
        
        flash("Student deleted successfully!", "success")
        return redirect(url_for("record_lists"))
    except sqlite3.Error as e:
        flash(f"Error deleting student: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("record_lists"))

# ---------------------- EDIT STUDENT ---------------------- #

@app.route("/edit_student/<int:id>", methods=["GET", "POST"])
def edit_student(id):
    if not session.get("logged_in"):
        if request.method == "POST":
            return jsonify({"success": False, "message": "Not logged in"}), 401
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot edit students
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            if request.method == "POST":
                return jsonify({"success": False, "message": "You don't have permission to edit students."}), 403
            flash("You don't have permission to edit students.", "danger")
            db.close()
            return redirect(url_for("dashboard"))
        db.close()
    
    db = get_db_connection()
    if not db:
        if request.method == "POST":
            return jsonify({"success": False, "message": "Database connection error"}), 500
        flash("Database connection error.", "danger")
        return redirect(url_for("student_list"))
    
    try:
        cursor = db.cursor()    
        cursor.execute("SELECT * FROM students WHERE id = ?", (id,))
        student = cursor.fetchone()
        
        if not student:
            if request.method == "POST":
                return jsonify({"success": False, "message": "Student not found"}), 404
            flash("Student not found.", "danger")
            db.close()
            return redirect(url_for("record_lists"))
        
        if request.method == "POST":
            # Collect raw data
            student_data_raw = {
                "studentLRN": request.form.get("studentLRN", "").strip(),
                "name": request.form.get("name", "").strip(),
                "class": request.form.get("class", "").strip(),
                "dob": request.form.get("dob") or None,
                "address": request.form.get("address", "").strip() or None,
                "parentContact": request.form.get("parentContact", "").strip() or None,
                "emergencyContact": request.form.get("emergencyContact", "").strip() or None,
                "height": request.form.get("height", "").strip() or None,
                "weight": request.form.get("weight", "").strip() or None,
                "blood": request.form.get("blood", "").strip() or None,
                "pastIllnesses": request.form.get("pastIllnesses", "").strip() or None,
                "allergies": request.form.get("allergies", "").strip() or None,
                "conditions": request.form.get("conditions", "").strip() or None,
                "vaccination": request.form.get("vaccination", "").strip() or None,
                "strand": request.form.get("strand", "").strip() or None,
            }
            
            if not student_data_raw["studentLRN"] or not student_data_raw["name"] or not student_data_raw["class"]:
                return jsonify({"success": False, "message": "Student LRN, Name, and Class are required fields."}), 400
            
            # Encrypt sensitive fields
            student_data = student_data_raw.copy()
            if encryption_handler:
                for field in ['allergies', 'conditions', 'pastIllnesses', 'parentContact', 'emergencyContact', 'address', 'strand']:
                    if student_data[field]:
                        try:
                            student_data[field] = encryption_handler.encrypt(student_data[field])
                        except Exception as e:
                            print(f"Encryption error for field {field}: {e}")
            
            student_data_tuple = (
                student_data["studentLRN"],
                student_data["name"],
                student_data["class"],
                student_data["dob"],
                student_data["address"],
                student_data["parentContact"],
                student_data["emergencyContact"],
                student_data["height"],
                student_data["weight"],
                student_data["blood"],
                student_data["pastIllnesses"],
                student_data["allergies"],
                student_data["conditions"],
                student_data["vaccination"],
                student_data["strand"],
                id
            )
            
            cursor.execute("""
                UPDATE students SET
                    studentLRN=?, name=?, class=?, dob=?, address=?,
                    parentContact=?, emergencyContact=?,
                    height=?, weight=?, blood=?,
                    pastIllnesses=?, allergies=?, conditions=?, vaccination=?, strand=?
                WHERE id=?
            """, student_data_tuple)
            
            db.commit()
            db.close()
            
            return jsonify({"success": True, "message": "Student updated successfully!"}), 200
        
        db.close()
        return render_template("records/edit_student.html", student=student)
        
    except sqlite3.Error as e:
        if request.method == "POST":
            if db:
                db.close()
            return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
        else:
            flash(f"Error: {str(e)}", "danger")
            if db:
                db.close()
            return redirect(url_for("record_lists"))

# ---------------------- DELETE TEACHER ---------------------- #

@app.route("/delete_teacher/<int:id>", methods=["POST"])
def delete_teacher(id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot delete teachers
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            flash("You don't have permission to delete teachers.", "danger")
            db.close()
            return redirect(url_for("dashboard"))
        db.close()
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("teacher_list"))
    
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM teachers WHERE id = ?", (id,))
        db.commit()
        db.close()
        
        flash("Teacher deleted successfully!", "success")
        return redirect(url_for("record_lists"))
    except sqlite3.Error as e:
        flash(f"Error deleting teacher: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("record_lists"))

# ---------------------- EDIT TEACHER ---------------------- #

@app.route("/edit_teacher/<int:id>", methods=["GET", "POST"])
def edit_teacher(id):
    if not session.get("logged_in"):
        if request.method == "POST":
            return jsonify({"success": False, "message": "Not logged in"}), 401
        return redirect(url_for("login"))
    
    # Check if user is class advisor - they cannot edit teachers
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            if request.method == "POST":
                return jsonify({"success": False, "message": "You don't have permission to edit teachers."}), 403
            flash("You don't have permission to edit teachers.", "danger")
            db.close()
            return redirect(url_for("dashboard"))
        db.close()
    
    db = get_db_connection()
    if not db:
        if request.method == "POST":
            return jsonify({"success": False, "message": "Database connection error"}), 500
        flash("Database connection error.", "danger")
        return redirect(url_for("teacher_list"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM teachers WHERE id = ?", (id,))
        teacher = cursor.fetchone()
        
        if not teacher:
            if request.method == "POST":
                return jsonify({"success": False, "message": "Teacher not found"}), 404
            flash("Teacher not found.", "danger")
            db.close()
            return redirect(url_for("record_lists"))
        
        if request.method == "POST":
            # Collect raw data
            teacher_data_raw = {
                "teacherID": request.form.get("teacherID", "").strip(),
                "name": request.form.get("name", "").strip(),
                "department": request.form.get("department", "").strip(),
                "dob": request.form.get("dob") or None,
                "address": request.form.get("address", "").strip() or None,
                "contact": request.form.get("contact", "").strip() or None,
                "height": request.form.get("height", "").strip() or None,
                "weight": request.form.get("weight", "").strip() or None,
                "blood": request.form.get("blood", "").strip() or None,
                "pastIllnesses": request.form.get("pastIllnesses", "").strip() or None,
                "allergies": request.form.get("allergies", "").strip() or None,
                "conditions": request.form.get("conditions", "").strip() or None,
                "vaccination": request.form.get("vaccination", "").strip() or None,
            }
            
            if not teacher_data_raw["teacherID"] or not teacher_data_raw["name"] or not teacher_data_raw["department"]:
                return jsonify({"success": False, "message": "Teacher ID, Name, and Department are required fields."}), 400
            
            # Encrypt sensitive fields
            teacher_data = teacher_data_raw.copy()
            if encryption_handler:
                for field in ['allergies', 'conditions', 'pastIllnesses', 'contact', 'address']:
                    if teacher_data[field]:
                        try:
                            teacher_data[field] = encryption_handler.encrypt(teacher_data[field])
                        except Exception as e:
                            print(f"Encryption error for field {field}: {e}")
            
            teacher_data_tuple = (
                teacher_data["teacherID"],
                teacher_data["name"],
                teacher_data["department"],
                teacher_data["dob"],
                teacher_data["address"],
                teacher_data["contact"],
                teacher_data["height"],
                teacher_data["weight"],
                teacher_data["blood"],
                teacher_data["pastIllnesses"],
                teacher_data["allergies"],
                teacher_data["conditions"],
                teacher_data["vaccination"],
                id
            )
            
            cursor.execute("""
                UPDATE teachers SET
                    teacherID=?, name=?, department=?, dob=?, address=?,
                    contact=?, height=?, weight=?, blood=?,
                    pastIllnesses=?, allergies=?, conditions=?, vaccination=?
                WHERE id=?
            """, teacher_data_tuple)
            
            db.commit()
            db.close()
            
            return jsonify({"success": True, "message": "Teacher updated successfully!"}), 200
        
        db.close()
        return render_template("records/edit_teacher.html", teacher=teacher)
        
    except sqlite3.Error as e:
        if request.method == "POST":
            if db:
                db.close()
            return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
        else:
            flash(f"Error: {str(e)}", "danger")
            if db:
                db.close()
            return redirect(url_for("record_lists"))
        if db:
            db.close()
        return redirect(url_for("record_lists"))

# ---------------------- INVENTORY ---------------------- #

@app.route("/inventory")
def inventory():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database connection error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Check if user is class advisor - they cannot access inventory
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            db.close()
            flash("You don't have permission to access inventory.", "danger")
            return redirect(url_for("dashboard"))
        
        # Get inventory items
        cursor.execute("SELECT * FROM inventory ORDER BY category, item_name")
        inventory_items = cursor.fetchall()
        db.close()
        
        response = render_template("admin/inventory.html", inventory=inventory_items)
        # Disable caching
        resp = Response(response)
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    except sqlite3.Error as e:
        flash(f"Error loading inventory: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("dashboard"))

# ---------------------- ADD MEDICINE ---------------------- #

@app.route("/add_medicine", methods=["GET", "POST"])
def add_medicine():
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Not logged in"}), 401
    
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database connection error"}), 500
    
    try:
        # Check if user is class advisor - they cannot add medicine
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            db.close()
            return jsonify({"success": False, "message": "You don't have permission to add medicine."}), 403
        
        if request.method == "POST":
            item_name = request.form.get("item_name", "").strip()
            category = request.form.get("category", "").strip()
            quantity = request.form.get("quantity", "").strip()
            unit = request.form.get("unit", "").strip()
            status = request.form.get("status", "available").strip()
            expiry_date = request.form.get("expiry_date", "").strip()
            reorder_level = request.form.get("reorder_level", "0").strip()
            supplier = request.form.get("supplier", "").strip()
            notes = request.form.get("notes", "").strip()
            
            # Validation
            if not all([item_name, category, quantity, unit]):
                return jsonify({"success": False, "message": "Please fill in all required fields."}), 400
            
            try:
                quantity = int(quantity)
                reorder_level = int(reorder_level)
            except ValueError:
                return jsonify({"success": False, "message": "Quantity and reorder level must be valid numbers."}), 400
            
            try:
                cursor = db.cursor()
                cursor.execute(
                    """INSERT INTO inventory 
                       (item_name, category, quantity, unit, status, expiry_date, reorder_level, supplier, notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (item_name, category, quantity, unit, status, expiry_date or None, reorder_level, supplier, notes)
                )
                db.commit()
                db.close()
                
                return jsonify({"success": True, "message": f"Medicine '{item_name}' added successfully!"}), 200
            except sqlite3.Error as e:
                db.close()
                return jsonify({"success": False, "message": f"Error adding medicine: {str(e)}"}), 500
        
        db.close()
        return render_template("admin/add_medicine.html")
    
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": f"Unexpected error: {str(e)}"}), 500

# ---------------------- DELETE MEDICINE ---------------------- #

@app.route("/delete_medicine/<int:id>", methods=["POST"])
def delete_medicine(id):
    if not session.get("logged_in"):
        return {"success": False, "message": "Not logged in"}, 401
    
    db = get_db_connection()
    if not db:
        return {"success": False, "message": "Database connection error"}, 500
    
    try:
        cursor = db.cursor()
        
        # Check if user is class advisor - they cannot delete medicine
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        if user and safe_row_get(user, 'role') == 'class_advisor':
            db.close()
            return {"success": False, "message": "You don't have permission to delete medicine."}, 403
        
        # Get medicine name before deleting
        cursor.execute("SELECT item_name FROM inventory WHERE id = ?", (id,))
        result = cursor.fetchone()
        
        if result:
            medicine_name = result[0]
            cursor.execute("DELETE FROM inventory WHERE id = ?", (id,))
            db.commit()
            db.close()
            return {"success": True, "message": f"Medicine '{medicine_name}' deleted successfully!"}, 200
        else:
            db.close()
            return {"success": False, "message": "Medicine not found"}, 404
        
    except sqlite3.Error as e:
        if db:
            db.close()
        return {"success": False, "message": f"Error deleting medicine: {str(e)}"}, 500

# ---------------------- NOTIFICATIONS & ALERTS ---------------------- #

@app.route("/api/notifications", methods=["GET"])
def api_get_notifications():
    """Get notifications for header (admin only) - pending user approvals"""
    if not session.get("logged_in"):
        return jsonify({"notifications": [], "total_count": 0, "unread_count": 0}), 401
    
    db = get_db_connection()
    if not db:
        return jsonify({"error": "Database connection error"}), 500
    
    try:
        cursor = db.cursor()
        
        # Get user's role
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user_role_row = cursor.fetchone()
        user_role = safe_row_get(user_role_row, 'role', 'health_officer') if user_role_row else 'health_officer'
        
        notifications = []
        
        # Only show pending approvals to super_admin users
        if user_role == 'super_admin':
            cursor.execute("""
                SELECT id, fullname, email, created_at, advisory_class 
                FROM users 
                WHERE role = 'pending' 
                ORDER BY created_at DESC
            """)
            pending_users = cursor.fetchall()
            
            for user in pending_users:
                user_id = safe_row_get(user, 'id')
                fullname = safe_row_get(user, 'fullname')
                email = safe_row_get(user, 'email')
                advisory_class = safe_row_get(user, 'advisory_class')
                created_at = safe_row_get(user, 'created_at')
                
                # Build message with advisory class if available
                class_info = f" | Section: {advisory_class}" if advisory_class else ""
                message = f"{fullname} ({email}){class_info} is awaiting role assignment"
                
                # Use actual creation time from database
                timestamp = created_at if created_at else datetime.now().isoformat()
                
                notifications.append({
                    'id': f"pending_user_{user_id}",
                    'type': 'pending_approval',
                    'title': 'New User Pending Approval',
                    'message': message,
                    'icon': 'bx-user-plus',
                    'priority': 'high',
                    'timestamp': timestamp,
                    'link': '/manage-users'
                })
        
        db.close()
        
        return jsonify({
            "notifications": notifications,
            "total_count": len(notifications),
            "unread_count": len(notifications)
        }), 200
    
    except Exception as e:
        print(f"Error in api_get_notifications: {e}")
        return jsonify({"error": str(e), "notifications": []}), 500

@app.route("/api/notifications/dismiss", methods=["POST"])
def dismiss_notification():
    """Dismiss a notification (stores in browser's localStorage via frontend)"""
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        data = request.get_json()
        notification_id = data.get("notification_id")
        
        if not notification_id:
            return jsonify({"error": "notification_id is required"}), 400
        
        # The actual dismissal is handled on the frontend with localStorage
        # This endpoint can be used for logging dismissals if needed
        print(f"User {session.get('user_id')} dismissed notification: {notification_id}")
        
        return jsonify({"success": True, "message": "Notification dismissed"}), 200
    
    except Exception as e:
        print(f"Error in dismiss_notification: {e}")
        return jsonify({"error": str(e)}), 500


# ---------------------- HEALTH ANALYTICS & STATISTICS ---------------------- #

def get_blood_type_distribution():
    """Get blood type distribution for students and teachers"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        blood_distribution = {}
        
        # Count student blood types
        cursor.execute("SELECT blood, COUNT(*) as count FROM students WHERE blood IS NOT NULL AND blood != '' GROUP BY blood")
        students_blood = cursor.fetchall()
        
        # Count teacher blood types
        cursor.execute("SELECT blood, COUNT(*) as count FROM teachers WHERE blood IS NOT NULL AND blood != '' GROUP BY blood")
        teachers_blood = cursor.fetchall()
        
        # Combine data
        for blood_type, count in students_blood:
            blood_distribution[blood_type] = blood_distribution.get(blood_type, 0) + count
        
        for blood_type, count in teachers_blood:
            blood_distribution[blood_type] = blood_distribution.get(blood_type, 0) + count
        
        db.close()
        return dict(sorted(blood_distribution.items()))
    
    except Exception as e:
        print(f"Error getting blood type distribution: {e}")
        if db:
            db.close()
        return {}

def get_allergy_statistics():
    """Get common allergies in the system"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        allergy_list = []
        
        # Get student allergies
        cursor.execute("SELECT allergies FROM students WHERE allergies IS NOT NULL AND allergies != ''")
        students_allergies = cursor.fetchall()
        
        # Get teacher allergies
        cursor.execute("SELECT allergies FROM teachers WHERE allergies IS NOT NULL AND allergies != ''")
        teachers_allergies = cursor.fetchall()
        
        # Parse and count allergies (they may be comma-separated)
        all_allergies = list(students_allergies) + list(teachers_allergies)
        allergy_count = {}
        
        for record in all_allergies:
            allergies = record[0]
            # Split by comma and clean up
            allergies_list = [a.strip() for a in allergies.split(',')]
            for allergy in allergies_list:
                if allergy:
                    allergy_count[allergy] = allergy_count.get(allergy, 0) + 1
        
        # Sort by count and get top 10
        top_allergies = dict(sorted(allergy_count.items(), key=lambda x: x[1], reverse=True)[:10])
        db.close()
        return top_allergies
    
    except Exception as e:
        print(f"Error getting allergy statistics: {e}")
        if db:
            db.close()
        return {}

def get_vaccination_status():
    """Get vaccination status distribution"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        vaccination_status = {}
        
        # Count student vaccination statuses
        cursor.execute("SELECT vaccination, COUNT(*) as count FROM students WHERE vaccination IS NOT NULL AND vaccination != '' GROUP BY vaccination")
        students_vacc = cursor.fetchall()
        
        # Count teacher vaccination statuses
        cursor.execute("SELECT vaccination, COUNT(*) as count FROM teachers WHERE vaccination IS NOT NULL AND vaccination != '' GROUP BY vaccination")
        teachers_vacc = cursor.fetchall()
        
        # Combine
        for vacc_status, count in students_vacc:
            vaccination_status[vacc_status] = vaccination_status.get(vacc_status, 0) + count
        
        for vacc_status, count in teachers_vacc:
            vaccination_status[vacc_status] = vaccination_status.get(vacc_status, 0) + count
        
        db.close()
        return dict(sorted(vaccination_status.items()))
    
    except Exception as e:
        print(f"Error getting vaccination status: {e}")
        if db:
            db.close()
        return {}

def get_past_illnesses_trends():
    """Get frequency of past illnesses"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        illness_count = {}
        
        # Get student illnesses
        cursor.execute("SELECT pastIllnesses FROM students WHERE pastIllnesses IS NOT NULL AND pastIllnesses != ''")
        students_illnesses = cursor.fetchall()
        
        # Get teacher illnesses
        cursor.execute("SELECT pastIllnesses FROM teachers WHERE pastIllnesses IS NOT NULL AND pastIllnesses != ''")
        teachers_illnesses = cursor.fetchall()
        
        # Parse and count illnesses (may be comma-separated)
        all_illnesses = list(students_illnesses) + list(teachers_illnesses)
        
        for record in all_illnesses:
            illnesses = record[0]
            # Split by comma and clean up
            illness_list = [i.strip() for i in illnesses.split(',')]
            for illness in illness_list:
                if illness:
                    illness_count[illness] = illness_count.get(illness, 0) + 1
        
        # Sort by count and get top 10
        top_illnesses = dict(sorted(illness_count.items(), key=lambda x: x[1], reverse=True)[:10])
        db.close()
        return top_illnesses
    
    except Exception as e:
        print(f"Error getting illness trends: {e}")
        if db:
            db.close()
        return {}

def get_health_conditions_stats():
    """Get statistics on pre-existing health conditions"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        conditions_count = {}
        
        # Get student conditions
        cursor.execute("SELECT conditions FROM students WHERE conditions IS NOT NULL AND conditions != ''")
        students_conditions = cursor.fetchall()
        
        # Get teacher conditions
        cursor.execute("SELECT conditions FROM teachers WHERE conditions IS NOT NULL AND conditions != ''")
        teachers_conditions = cursor.fetchall()
        
        # Parse and count conditions
        all_conditions = list(students_conditions) + list(teachers_conditions)
        
        for record in all_conditions:
            conditions = record[0]
            # Split by comma and clean up
            condition_list = [c.strip() for c in conditions.split(',')]
            for condition in condition_list:
                if condition:
                    conditions_count[condition] = conditions_count.get(condition, 0) + 1
        
        # Sort by count and get top 10
        top_conditions = dict(sorted(conditions_count.items(), key=lambda x: x[1], reverse=True)[:10])
        db.close()
        return top_conditions
    
    except Exception as e:
        print(f"Error getting conditions stats: {e}")
        if db:
            db.close()
        return {}

def get_health_summary():
    """Get overall health summary statistics"""
    db = get_db_connection()
    if not db:
        return {}
    
    try:
        cursor = db.cursor()
        
        # Count total students and teachers
        cursor.execute("SELECT COUNT(*) as count FROM students")
        total_students = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as count FROM teachers")
        total_teachers = cursor.fetchone()[0]
        
        # Count students with allergies
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE allergies IS NOT NULL AND allergies != ''")
        students_with_allergies = cursor.fetchone()[0]
        
        # Count students with pre-existing conditions
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE conditions IS NOT NULL AND conditions != ''")
        students_with_conditions = cursor.fetchone()[0]
        
        # Count teachers with allergies
        cursor.execute("SELECT COUNT(*) as count FROM teachers WHERE allergies IS NOT NULL AND allergies != ''")
        teachers_with_allergies = cursor.fetchone()[0]
        
        # Count teachers with pre-existing conditions
        cursor.execute("SELECT COUNT(*) as count FROM teachers WHERE conditions IS NOT NULL AND conditions != ''")
        teachers_with_conditions = cursor.fetchone()[0]
        
        # Count pending vaccinations
        cursor.execute("SELECT COUNT(*) as count FROM students WHERE vaccination LIKE '%pending%' OR vaccination LIKE '%due%'")
        pending_vaccinations = cursor.fetchone()[0]
        
        # Get inventory alerts
        from datetime import datetime, timedelta
        today = datetime.now().date()
        cursor.execute("SELECT COUNT(*) as count FROM inventory WHERE expiry_date IS NOT NULL AND expiry_date < ?", (str(today),))
        expired_items = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as count FROM inventory WHERE expiry_date IS NOT NULL AND expiry_date BETWEEN ? AND ?", 
                      (str(today), str(today + timedelta(days=30))))
        expiring_soon = cursor.fetchone()[0]
        
        db.close()
        
        return {
            'total_students': total_students,
            'total_teachers': total_teachers,
            'students_with_allergies': students_with_allergies,
            'students_with_conditions': students_with_conditions,
            'teachers_with_allergies': teachers_with_allergies,
            'teachers_with_conditions': teachers_with_conditions,
            'pending_vaccinations': pending_vaccinations,
            'expired_items': expired_items,
            'expiring_soon': expiring_soon
        }
    
    except Exception as e:
        print(f"Error getting health summary: {e}")
        if db:
            db.close()
        return {}

# ---------------------- ADVANCED MANAGEMENT ---------------------- #

@app.route("/advanced-management")
@require_role('super_admin', 'health_officer')
def advanced_management():
    """Advanced management dashboard"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get user statistics
        cursor.execute("SELECT COUNT(*) as count FROM users WHERE is_active = 1")
        total_users = cursor.fetchone()['count']
        
        # Get recent audit logs
        cursor.execute("""
            SELECT * FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT 20
        """)
        recent_logs = cursor.fetchall()
        
        # Get backup history
        cursor.execute("""
            SELECT * FROM backup_log 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        backups = cursor.fetchall()
        
        db.close()
        
        return render_template("admin/advanced_management.html", 
                             total_users=total_users,
                             recent_logs=recent_logs,
                             backups=backups,
                             roles=ROLES)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

# ---------------------- USER ROLE MANAGEMENT ---------------------- #

@app.route("/manage-users")
@require_role('super_admin')
def manage_users():
    """Manage user roles and permissions"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
        users = cursor.fetchall()
        
        # Get list of classes for assignment
        cursor.execute("SELECT DISTINCT class FROM students ORDER BY class")
        classes = [row[0] for row in cursor.fetchall()]
        
        db.close()
        
        return render_template("admin/manage_users.html", users=users, roles=ROLES, classes=classes)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("advanced_management"))

@app.route("/api/user/<int:user_id>/role", methods=["POST"])
def update_user_role(user_id):
    """Update user role"""
    # Check if user is logged in and is super_admin
    if not session.get("logged_in"):
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            return jsonify({'success': False, 'message': 'Only super admin can update roles'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    data = request.get_json()
    new_role = data.get('role')
    
    if new_role not in ROLES:
        return jsonify({'success': False, 'message': 'Invalid role'}), 400
    
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        
        # Get old role for audit
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        old_data = cursor.fetchone()
        old_role = old_data['role'] if old_data else None
        
        # Update role
        cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        db.commit()
        
        # Audit log
        log_audit("UPDATE", "users", user_id, 
                 {'role': old_role}, 
                 {'role': new_role})
        
        db.close()
        return jsonify({'success': True, 'message': 'Role updated successfully'})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/user/<int:user_id>/advisory-class", methods=["POST"])
def update_advisory_class(user_id):
    """Update class advisor's assigned advisory class"""
    print(f"[API] POST /api/user/{user_id}/advisory-class - Advisory class assignment request")
    
    # Check if user is logged in and is super_admin
    if not session.get("logged_in"):
        print("[API] Not logged in")
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            print(f"[API] User {session.get('user_id')} is not super_admin")
            return jsonify({'success': False, 'message': 'Only super admin can assign advisory classes'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    data = request.get_json()
    advisory_class = data.get('advisory_class', '').strip()
    print(f"[API] Advisory class to assign: '{advisory_class}'")
    
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        
        # Verify user exists and has class_advisor role
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"[API] User {user_id} not found")
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if safe_row_get(user, 'role') != 'class_advisor':
            print(f"[API] User {user_id} is not a class_advisor, role is {safe_row_get(user, 'role')}")
            return jsonify({'success': False, 'message': 'User is not a class advisor'}), 400
        
        old_advisory_class = safe_row_get(user, 'advisory_class')
        print(f"[API] Old advisory class: {old_advisory_class}, New: {advisory_class}")
        
        # Update advisory class
        cursor.execute("UPDATE users SET advisory_class = ? WHERE id = ?", (advisory_class or None, user_id))
        db.commit()
        
        # Verify update
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        updated = cursor.fetchone()
        print(f"[API] After update - advisory_class in DB: {updated[0] if updated else 'NOT FOUND'}")
        
        # Audit log
        log_audit("UPDATE", "users", user_id, 
                 {'advisory_class': old_advisory_class}, 
                 {'advisory_class': advisory_class})
        
        db.close()
        print(f"[API] Successfully updated user {user_id} advisory class to '{advisory_class}'")
        return jsonify({'success': True, 'message': f'Advisory class updated to {advisory_class if advisory_class else "None"}'})
    except sqlite3.Error as e:
        print(f"[API] Database error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/user/<int:user_id>/status", methods=["POST"])
def update_user_status(user_id):
    """Activate/deactivate user"""
    # Check if user is logged in and is super_admin
    if not session.get("logged_in"):
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            return jsonify({'success': False, 'message': 'Only super admin can change user status'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    data = request.get_json()
    is_active = data.get('is_active')
    
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))
        db.commit()
        
        log_audit("UPDATE", "users", user_id, {}, {'is_active': is_active})
        
        db.close()
        return jsonify({'success': True, 'message': 'User status updated'})
    except sqlite3.Error as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/user/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    """Delete a user account"""
    # Check if user is logged in and is super_admin
    if not session.get("logged_in"):
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    db = get_db_connection()
    if db:
        cursor = db.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (session.get("user_id"),))
        user = cursor.fetchone()
        db.close()
        
        if not user or safe_row_get(user, 'role') != 'super_admin':
            return jsonify({'success': False, 'message': 'Only super admin can delete users'}), 403
    else:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    # Prevent deleting own account
    if user_id == session.get("user_id"):
        return jsonify({'success': False, 'message': 'You cannot delete your own account'}), 400
    
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        
        # Get user info before deletion for audit log
        cursor.execute("SELECT username, fullname, email, role FROM users WHERE id = ?", (user_id,))
        user_info = cursor.fetchone()
        
        if not user_info:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Delete the user
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        
        # Log the deletion
        log_audit("DELETE", "users", user_id, 
                  {'username': safe_row_get(user_info, 'username'),
                   'fullname': safe_row_get(user_info, 'fullname'),
                   'email': safe_row_get(user_info, 'email'),
                   'role': safe_row_get(user_info, 'role')},
                  {})
        
        db.close()
        return jsonify({'success': True, 'message': f"User {safe_row_get(user_info, 'username')} has been deleted successfully"})
    except sqlite3.Error as e:
        db.close()
        return jsonify({'success': False, 'message': str(e)}), 500

# ---------------------- CLASS ADVISOR BMI & DEWORMING RECORDS ---------------------- #

@app.route("/class-advisor/bmi-add", methods=["GET", "POST"])
@require_role('class_advisor')
def class_advisor_bmi_add():
    """Class advisor add BMI record for their section"""
    user_id = session.get("user_id")
    
    if request.method == "POST":
        try:
            person_type = "student"
            person_id = request.form.get("person_id", "").strip()
            student_name = request.form.get("student_name", "").strip()
            birthdate = request.form.get("birthdate", "").strip()
            height = request.form.get("height", "").strip()
            weight = request.form.get("weight", "").strip()
            semester = request.form.get("semester", "1st Semester").strip()
            nutritional_status = request.form.get("nutritional_status", "").strip()
            height_for_age = request.form.get("height_for_age", "").strip()
            remarks = request.form.get("remarks", "").strip()
            record_date = request.form.get("record_date", "").strip()
            
            # Validate required fields
            if not all([student_name, record_date, height, weight]):
                return jsonify({"success": False, "message": "Please fill in all required fields."}), 400
            
            try:
                height = float(height)
                weight = float(weight)
            except ValueError:
                return jsonify({"success": False, "message": "Height and weight must be valid numbers."}), 400
            
            # Calculate BMI - 6 Tier System
            if height > 0:
                bmi = weight / (height * height)
                if bmi < 15:
                    bmi_category = "Severely wasted"
                elif bmi < 18.5:
                    bmi_category = "Wasted"
                elif bmi < 25:
                    bmi_category = "Normal"
                elif bmi < 30:
                    bmi_category = "Overweight"
                elif bmi <= 40:
                    bmi_category = "Obese"
                else:
                    bmi_category = "Morbidly Obese"
            else:
                bmi = None
                bmi_category = None
            
            # Get user's section
            db = get_db_connection()
            if not db:
                return jsonify({"success": False, "message": "Database connection error"}), 500
            
            cursor = db.cursor()
            cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            advisory_class = safe_row_get(user, 'advisory_class') if user else None
            
            if not advisory_class:
                db.close()
                return jsonify({"success": False, "message": "You have not been assigned an advisory class."}), 403
            
            # Use a default person_id if not provided
            if not person_id:
                person_id = "0"  # Placeholder for records added without a specific student ID
            
            # Insert BMI record
            cursor.execute("""
                INSERT INTO bmi_records 
                (person_type, person_id, record_date, name, birthdate, grade, section, 
                 height, weight, bmi, bmi_category, nutritional_status, height_for_age, 
                 remarks, recorded_by, recorded_by_name, semester)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (person_type, person_id, record_date, student_name, birthdate or None, 
                  advisory_class, advisory_class, height, weight, bmi, bmi_category, 
                  nutritional_status, height_for_age, remarks, user_id, session.get("username"), semester))
            
            db.commit()
            record_id = cursor.lastrowid
            db.close()
            
            log_audit("CREATE", "bmi_records", record_id, {}, 
                     {"name": student_name, "section": advisory_class, "semester": semester})
            
            return jsonify({"success": True, "message": "BMI record added successfully!"}), 200
        except Exception as e:
            print(f"Error adding BMI record: {str(e)}")
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500
    
    # GET request - show form
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get class advisor's section
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        advisory_class = safe_row_get(user, 'advisory_class') if user else None
        
        if not advisory_class:
            db.close()
            flash("You have not been assigned an advisory class.", "danger")
            return redirect(url_for("dashboard"))
        
        # Get students in the section
        cursor.execute("""
            SELECT id, studentLRN, name, dob 
            FROM students 
            WHERE class = ?
            ORDER BY name ASC
        """, (advisory_class,))
        students = cursor.fetchall()
        db.close()
        
        return render_template("admin/class_advisor_bmi_add.html", 
                             students=students, 
                             advisory_class=advisory_class)
    except Exception as e:
        db.close()
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/class-advisor/deworming-add", methods=["GET", "POST"])
@require_role('class_advisor')
def class_advisor_deworming_add():
    """Class advisor add deworming record for their section"""
    user_id = session.get("user_id")
    
    if request.method == "POST":
        try:
            person_type = "student"
            person_id = request.form.get("person_id", "").strip()
            student_name = request.form.get("student_name", "").strip()
            lrn = request.form.get("lrn", "").strip()
            school_year = request.form.get("school_year", "").strip()
            recorded_date = request.form.get("recorded_date", "").strip()
            
            # Pre-deworming fields
            pre_4ps_recipient = request.form.get("pre_4ps_recipient", "No").strip()
            pre_4ps_with_consent = request.form.get("pre_4ps_with_consent", "No").strip()
            pre_non_4ps_consent = request.form.get("pre_non_4ps_consent", "No").strip()
            pre_deworming_consent = request.form.get("pre_deworming_consent", "No").strip()
            
            # Post-deworming fields
            post_4ps_children = request.form.get("post_4ps_children", "No").strip()
            post_non_4ps_children = request.form.get("post_non_4ps_children", "No").strip()
            post_serious_illness = request.form.get("post_serious_illness", "No").strip()
            post_adverse_effect = request.form.get("post_adverse_effect", "No").strip()
            
            remarks = request.form.get("remarks", "").strip()
            
            if not all([student_name, school_year, recorded_date]):
                return jsonify({"success": False, "message": "Please fill in all required fields."}), 400
            
            # Get user's section
            db = get_db_connection()
            if not db:
                return jsonify({"success": False, "message": "Database connection error"}), 500
            
            cursor = db.cursor()
            cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            advisory_class = safe_row_get(user, 'advisory_class') if user else None
            
            if not advisory_class:
                db.close()
                return jsonify({"success": False, "message": "You have not been assigned an advisory class."}), 403
            
            # Use a default person_id if not provided
            if not person_id:
                person_id = "0"  # Placeholder for records added without a specific student ID
            
            # Insert deworming record
            cursor.execute("""
                INSERT INTO deworming_records 
                (person_type, person_id, name, grade, section, lrn, school_year, 
                 pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent, pre_deworming_consent,
                 post_4ps_children, post_non_4ps_children, post_serious_illness, post_adverse_effect,
                 remarks, recorded_date, recorded_by, recorded_by_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (person_type, person_id, student_name, advisory_class, advisory_class, 
                  lrn, school_year, pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent,
                  pre_deworming_consent, post_4ps_children, post_non_4ps_children, post_serious_illness,
                  post_adverse_effect, remarks, recorded_date, user_id, session.get("username")))
            
            db.commit()
            record_id = cursor.lastrowid
            db.close()
            
            log_audit("CREATE", "deworming_records", record_id, {}, 
                     {"name": student_name, "section": advisory_class})
            
            return jsonify({"success": True, "message": "Deworming record added successfully!"}), 200
        except Exception as e:
            print(f"Error adding deworming record: {str(e)}")
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500
    
    # GET request - show form
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get class advisor's section
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        advisory_class = safe_row_get(user, 'advisory_class') if user else None
        
        if not advisory_class:
            db.close()
            flash("You have not been assigned an advisory class.", "danger")
            return redirect(url_for("dashboard"))
        
        # Get students in the section
        cursor.execute("""
            SELECT id, studentLRN, name 
            FROM students 
            WHERE class = ?
            ORDER BY name ASC
        """, (advisory_class,))
        students = cursor.fetchall()
        db.close()
        
        return render_template("admin/class_advisor_deworming_add.html", 
                             students=students, 
                             advisory_class=advisory_class)
    except Exception as e:
        db.close()
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/class-advisor/bmi-records")
@require_role('class_advisor')
def class_advisor_bmi_records():
    """View BMI records for the class advisor's section"""
    user_id = session.get("user_id")
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get class advisor's section
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        advisory_class = safe_row_get(user, 'advisory_class') if user else None
        
        if not advisory_class:
            db.close()
            flash("You have not been assigned an advisory class.", "danger")
            return redirect(url_for("dashboard"))
        
        # Get all BMI records for this section
        cursor.execute("""
            SELECT * FROM bmi_records 
            WHERE section = ?
            ORDER BY record_date DESC
        """, (advisory_class,))
        bmi_records = cursor.fetchall()
        
        # Get students for dropdown
        cursor.execute("SELECT id, name, dob, studentLRN FROM students WHERE section = ? ORDER BY name", (advisory_class,))
        students = cursor.fetchall()
        
        db.close()
        
        return render_template("admin/class_advisor_bmi_records.html",
                             advisory_class=advisory_class,
                             bmi_records=bmi_records,
                             students=students)
    except Exception as e:
        db.close()
        flash(f"Error loading BMI records: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/class-advisor/deworming-records")
@require_role('class_advisor')
def class_advisor_deworming_records():
    """View deworming records added by class advisor"""
    user_id = session.get("user_id")
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get class advisor's section
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        advisory_class = safe_row_get(user, 'advisory_class') if user else None
        
        if not advisory_class:
            db.close()
            flash("You have not been assigned an advisory class.", "danger")
            return redirect(url_for("dashboard"))
        
        # Get deworming records
        cursor.execute("""
            SELECT * FROM deworming_records 
            WHERE section = ?
            ORDER BY recorded_date DESC
        """, (advisory_class,))
        deworming_records = cursor.fetchall()
        
        # Get students for dropdown
        cursor.execute("SELECT id, name, dob, studentLRN FROM students WHERE section = ? ORDER BY name", (advisory_class,))
        students = cursor.fetchall()
        
        db.close()
        
        return render_template("admin/class_advisor_deworming_records.html",
                             advisory_class=advisory_class,
                             deworming_records=deworming_records,
                             students=students)
    except Exception as e:
        db.close()
        flash(f"Error loading deworming records: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/class-advisor/bmi-records/<int:record_id>/view")
@require_role('class_advisor')
def class_advisor_bmi_view(record_id):
    """View BMI record details"""
    user_id = session.get("user_id")
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        
        # Get user's section
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        advisory_class = safe_row_get(user, 'advisory_class')
        
        # Get record (verify it belongs to their section)
        cursor.execute("""
            SELECT * FROM bmi_records 
            WHERE id = ? AND section = ?
        """, (record_id, advisory_class))
        record = cursor.fetchone()
        
        db.close()
        
        if not record:
            return jsonify({"success": False, "message": "Record not found"}), 404
        
        return jsonify({
            "success": True,
            "record": dict(record)
        }), 200
    except Exception as e:
        db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/class-advisor/bmi-records/<int:record_id>/edit", methods=["GET", "POST"])
@require_role('class_advisor')
def class_advisor_bmi_edit(record_id):
    """Edit BMI record"""
    user_id = session.get("user_id")
    
    if request.method == "POST":
        try:
            height = request.form.get("height", "").strip()
            weight = request.form.get("weight", "").strip()
            semester = request.form.get("semester", "1st Semester").strip()
            nutritional_status = request.form.get("nutritional_status", "").strip()
            height_for_age = request.form.get("height_for_age", "").strip()
            remarks = request.form.get("remarks", "").strip()
            record_date = request.form.get("record_date", "").strip()
            
            if not all([record_date, height, weight]):
                return jsonify({"success": False, "message": "Please fill in all required fields."}), 400
            
            try:
                height = float(height)
                weight = float(weight)
            except ValueError:
                return jsonify({"success": False, "message": "Height and weight must be valid numbers."}), 400
            
            # Calculate BMI - 6 Tier System
            if height > 0:
                bmi = weight / (height * height)
                if bmi < 15:
                    bmi_category = "Severely wasted"
                elif bmi < 18.5:
                    bmi_category = "Wasted"
                elif bmi < 25:
                    bmi_category = "Normal"
                elif bmi < 30:
                    bmi_category = "Overweight"
                elif bmi <= 40:
                    bmi_category = "Obese"
                else:
                    bmi_category = "Morbidly Obese"
            else:
                bmi = None
                bmi_category = None
            
            db = get_db_connection()
            if not db:
                return jsonify({"success": False, "message": "Database connection error"}), 500
            
            cursor = db.cursor()
            
            # Get user's section and verify ownership
            cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            advisory_class = safe_row_get(user, 'advisory_class')
            
            # Get user's section
            cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            advisory_class = safe_row_get(user, 'advisory_class')
            
            cursor.execute("""
                SELECT * FROM bmi_records 
                WHERE id = ? AND section = ?
            """, (record_id, advisory_class))
            old_record = cursor.fetchone()
            
            if not old_record:
                db.close()
                return jsonify({"success": False, "message": "Record not found or access denied"}), 403
            
            cursor.execute("""
                UPDATE bmi_records 
                SET record_date = ?, height = ?, weight = ?, bmi = ?, bmi_category = ?,
                    nutritional_status = ?, height_for_age = ?, remarks = ?, semester = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (record_date, height, weight, bmi, bmi_category, nutritional_status, 
                  height_for_age, remarks, semester, record_id))
            
            db.commit()
            db.close()
            
            log_audit("UPDATE", "bmi_records", record_id, dict(old_record), 
                     {"height": height, "weight": weight, "bmi": bmi, "semester": semester})
            
            return jsonify({"success": True, "message": "BMI record updated successfully!"}), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route("/class-advisor/bmi-records/<int:record_id>/delete", methods=["POST"])
@require_role('class_advisor')
def class_advisor_bmi_delete(record_id):
    """Delete BMI record"""
    user_id = session.get("user_id")
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        
        # Get user's section
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        advisory_class = safe_row_get(user, 'advisory_class')
        
        # Get record (verify ownership by section)
        cursor.execute("""
            SELECT * FROM bmi_records 
            WHERE id = ? AND section = ?
        """, (record_id, advisory_class))
        record = cursor.fetchone()
        
        if not record:
            db.close()
            return jsonify({"success": False, "message": "Record not found"}), 404
        
        cursor.execute("DELETE FROM bmi_records WHERE id = ?", (record_id,))
        db.commit()
        db.close()
        
        log_audit("DELETE", "bmi_records", record_id, dict(record), {})
        
        return jsonify({"success": True, "message": "BMI record deleted successfully!"}), 200
    except Exception as e:
        db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/class-advisor/deworming-records/<int:record_id>/view")
@require_role('class_advisor')
def class_advisor_deworming_view(record_id):
    """View deworming record details"""
    user_id = session.get("user_id")
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        
        # Get user's section
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        advisory_class = safe_row_get(user, 'advisory_class')
        
        # Get record (verify it belongs to their section)
        cursor.execute("""
            SELECT * FROM deworming_records 
            WHERE id = ? AND section = ?
        """, (record_id, advisory_class))
        record = cursor.fetchone()
        
        db.close()
        
        if not record:
            return jsonify({"success": False, "message": "Record not found"}), 404
        
        return jsonify({
            "success": True,
            "record": dict(record)
        }), 200
    except Exception as e:
        db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/class-advisor/deworming-records/<int:record_id>/edit", methods=["GET", "POST"])
@require_role('class_advisor')
def class_advisor_deworming_edit(record_id):
    """Edit deworming record"""
    user_id = session.get("user_id")
    
    if request.method == "POST":
        try:
            pre_4ps_recipient = request.form.get("pre_4ps_recipient", "No").strip()
            pre_4ps_with_consent = request.form.get("pre_4ps_with_consent", "No").strip()
            pre_non_4ps_consent = request.form.get("pre_non_4ps_consent", "No").strip()
            pre_deworming_consent = request.form.get("pre_deworming_consent", "No").strip()
            post_4ps_children = request.form.get("post_4ps_children", "No").strip()
            post_non_4ps_children = request.form.get("post_non_4ps_children", "No").strip()
            post_serious_illness = request.form.get("post_serious_illness", "No").strip()
            post_adverse_effect = request.form.get("post_adverse_effect", "No").strip()
            remarks = request.form.get("remarks", "").strip()
            recorded_date = request.form.get("recorded_date", "").strip()
            
            if not recorded_date:
                return jsonify({"success": False, "message": "Please fill in all required fields."}), 400
            
            db = get_db_connection()
            if not db:
                return jsonify({"success": False, "message": "Database connection error"}), 500
            
            cursor = db.cursor()
            
            # Get user's section and verify ownership
            cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            advisory_class = safe_row_get(user, 'advisory_class')
            
            cursor.execute("""
                SELECT * FROM deworming_records 
                WHERE id = ? AND section = ?
            """, (record_id, advisory_class))
            old_record = cursor.fetchone()
            
            if not old_record:
                db.close()
                return jsonify({"success": False, "message": "Record not found or access denied"}), 403
            
            cursor.execute("""
                UPDATE deworming_records 
                SET pre_4ps_recipient = ?, pre_4ps_with_consent = ?, pre_non_4ps_consent = ?,
                    pre_deworming_consent = ?, post_4ps_children = ?, post_non_4ps_children = ?,
                    post_serious_illness = ?, post_adverse_effect = ?, remarks = ?,
                    recorded_date = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent,
                  pre_deworming_consent, post_4ps_children, post_non_4ps_children,
                  post_serious_illness, post_adverse_effect, remarks, recorded_date, record_id))
            
            db.commit()
            db.close()
            
            log_audit("UPDATE", "deworming_records", record_id, dict(old_record), {})
            
            return jsonify({"success": True, "message": "Deworming record updated successfully!"}), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route("/class-advisor/deworming-records/<int:record_id>/delete", methods=["POST"])
@require_role('class_advisor')
def class_advisor_deworming_delete(record_id):
    """Delete deworming record"""
    user_id = session.get("user_id")
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        
        # Get user's section
        cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        advisory_class = safe_row_get(user, 'advisory_class')
        
        # Get record (verify ownership by section)
        cursor.execute("""
            SELECT * FROM deworming_records 
            WHERE id = ? AND section = ?
        """, (record_id, advisory_class))
        record = cursor.fetchone()
        
        if not record:
            db.close()
            return jsonify({"success": False, "message": "Record not found"}), 404
        
        cursor.execute("DELETE FROM deworming_records WHERE id = ?", (record_id,))
        db.commit()
        db.close()
        
        log_audit("DELETE", "deworming_records", record_id, dict(record), {})
        
        return jsonify({"success": True, "message": "Deworming record deleted successfully!"}), 200
    except Exception as e:
        db.close()
        return jsonify({"success": False, "message": str(e)}), 500

# ---------------------- AUDIT LOG VIEWING ---------------------- #

@app.route("/audit-logs")
@require_role('super_admin', 'health_officer')
def audit_logs():
    """View audit logs"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get total count
        cursor.execute("SELECT COUNT(*) as count FROM audit_log")
        total = cursor.fetchone()['count']
        
        # Get paginated logs
        offset = (page - 1) * per_page
        cursor.execute("""
            SELECT * FROM audit_log 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        """, (per_page, offset))
        logs = cursor.fetchall()
        
        db.close()
        
        total_pages = (total + per_page - 1) // per_page
        
        return render_template("admin/audit_logs.html", 
                             logs=logs,
                             page=page,
                             total_pages=total_pages,
                             total=total)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("advanced_management"))

# ---------------------- BULK IMPORT/EXPORT ---------------------- #

@app.route("/import-export")
@require_role('super_admin', 'health_officer')
def import_export():
    """Bulk import/export page"""
    return render_template("admin/import_export.html")

@app.route("/api/import/students", methods=["POST"])
@require_role('super_admin', 'health_officer')
def import_students_csv():
    """Import students from CSV"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'message': 'Only CSV files allowed'}), 400
    
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        stream = io.TextIOWrapper(file.stream, encoding='utf-8')
        reader = csv.DictReader(stream)
        
        imported_count = 0
        errors = []
        
        for row in reader:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO students 
                    (studentLRN, name, class, dob, address, parentContact, emergencyContact, 
                     height, weight, blood, pastIllnesses, allergies, conditions, vaccination)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get('studentLRN'), row.get('name'), row.get('class'), row.get('dob'),
                    row.get('address'), row.get('parentContact'), row.get('emergencyContact'),
                    row.get('height'), row.get('weight'), row.get('blood'),
                    row.get('pastIllnesses'), row.get('allergies'), row.get('conditions'), row.get('vaccination')
                ))
                imported_count += 1
            except Exception as e:
                errors.append(f"Row error: {str(e)}")
        
        db.commit()
        log_audit("IMPORT", "students", None, {}, {'count': imported_count})
        db.close()
        
        return jsonify({'success': True, 'message': f'Imported {imported_count} students', 'errors': errors})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/api/import/teachers", methods=["POST"])
@require_role('super_admin', 'health_officer')
def import_teachers_csv():
    """Import teachers from CSV"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'success': False, 'message': 'Only CSV files allowed'}), 400
    
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        stream = io.TextIOWrapper(file.stream, encoding='utf-8')
        reader = csv.DictReader(stream)
        
        imported_count = 0
        errors = []
        
        for row in reader:
            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO teachers 
                    (teacherID, name, department, dob, address, contact, 
                     height, weight, blood, pastIllnesses, allergies, conditions, vaccination)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    row.get('teacherID'), row.get('name'), row.get('department'), row.get('dob'),
                    row.get('address'), row.get('contact'), row.get('height'), row.get('weight'),
                    row.get('blood'), row.get('pastIllnesses'), row.get('allergies'), 
                    row.get('conditions'), row.get('vaccination')
                ))
                imported_count += 1
            except Exception as e:
                errors.append(f"Row error: {str(e)}")
        
        db.commit()
        log_audit("IMPORT", "teachers", None, {}, {'count': imported_count})
        db.close()
        
        return jsonify({'success': True, 'message': f'Imported {imported_count} teachers', 'errors': errors})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ---------------------- DOCUMENT MANAGEMENT ---------------------- #

@app.route("/documents")
@require_role('super_admin', 'health_officer')
def document_management():
    """View all uploaded documents"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        cursor.execute("""
            SELECT * FROM documents 
            ORDER BY created_at DESC
        """)
        documents = cursor.fetchall()
        
        # Convert to list of dicts with file info
        doc_list = []
        for doc in documents:
            doc_dict = dict(doc)
            if os.path.exists(doc_dict['file_path']):
                doc_dict['file_exists'] = True
            else:
                doc_dict['file_exists'] = False
            doc_list.append(doc_dict)
        
        db.close()
        return render_template("admin/documents.html", documents=doc_list)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/documents/upload", methods=["GET", "POST"])
@require_role('super_admin', 'health_officer')
def upload_document():
    """Upload sensitive documents"""
    if request.method == "POST":
        try:
            # Check if file is in request
            if 'file' not in request.files:
                return jsonify({'success': False, 'message': 'No file provided'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'message': 'No file selected'}), 400
            
            # Validate file
            if not allowed_file(file.filename):
                return jsonify({'success': False, 'message': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400
            
            # Check file size
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            
            if file_size > MAX_FILE_SIZE:
                return jsonify({'success': False, 'message': f'File size exceeds {MAX_FILE_SIZE / 1024 / 1024:.0f}MB limit'}), 400
            
            # Get form data
            document_name = request.form.get('document_name', '')
            document_type = request.form.get('document_type', 'other')
            person_type = request.form.get('person_type', '')
            person_id = request.form.get('person_id', None)
            description = request.form.get('description', '')
            sensitivity_level = request.form.get('sensitivity_level', 'confidential')
            
            if not document_name:
                return jsonify({'success': False, 'message': 'Document name is required'}), 400
            
            # Create secure filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = file.filename.rsplit('.', 1)[1].lower()
            secure_fname = secure_filename(f"{timestamp}_{document_name}.{ext}")
            file_path = os.path.join(DOCUMENTS_DIR, secure_fname)
            
            # Save file
            file.save(file_path)
            
            # Log to database
            db = get_db_connection()
            cursor = db.cursor()
            
            cursor.execute("""
                INSERT INTO documents (
                    document_name, document_type, file_path, file_size,
                    person_type, person_id, description, sensitivity_level,
                    uploaded_by, uploaded_by_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                document_name, document_type, file_path, file_size,
                person_type if person_type else None, 
                int(person_id) if person_id else None,
                description, sensitivity_level,
                session.get('user_id'),
                session.get('username')
            ))
            
            db.commit()
            record_id = cursor.lastrowid
            
            log_audit("UPLOAD_DOCUMENT", "documents", record_id, {}, {
                'document': document_name,
                'type': document_type,
                'size': file_size,
                'sensitivity': sensitivity_level
            })
            
            db.close()
            
            return jsonify({
                'success': True, 
                'message': f'Document "{document_name}" uploaded successfully',
                'document_id': record_id
            }), 200
            
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    
    # GET request - show upload form
    try:
        db = get_db_connection()
        cursor = db.cursor()
        
        # Get list of students for linking
        cursor.execute("SELECT id, name FROM students ORDER BY name")
        students = [dict(row) for row in cursor.fetchall()]
        
        # Get list of teachers for linking
        cursor.execute("SELECT id, name FROM teachers ORDER BY name")
        teachers = [dict(row) for row in cursor.fetchall()]
        
        db.close()
        
        return render_template("admin/upload_document.html", 
                             students=students, 
                             teachers=teachers)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("document_management"))

@app.route("/documents/<int:doc_id>/view")
@require_role('super_admin', 'health_officer')
def view_document(doc_id):
    """View document (images display in page, others as API response)"""
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
        document = cursor.fetchone()
        db.close()
        
        if not document:
            return jsonify({'success': False, 'message': 'Document not found'}), 404
        
        file_path = document['file_path']
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'Document file not found on disk'}), 404
        
        # Log viewing
        try:
            log_audit("VIEW_DOCUMENT", "documents", doc_id, {}, {'document': document['document_name']})
        except:
            pass  # Don't fail if audit logging fails
        
        # Get file extension
        file_ext = file_path.rsplit('.', 1)[1].lower() if '.' in file_path else ''
        
        # For image files, return with proper MIME type and allow inline viewing
        if file_ext in ALLOWED_IMAGE_EXTENSIONS:
            mime_types = {
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg',
                'png': 'image/png',
                'gif': 'image/gif'
            }
            mimetype = mime_types.get(file_ext, 'image/jpeg')
            
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                return Response(
                    file_content,
                    mimetype=mimetype,
                    headers={"Content-Disposition": f"inline;filename={document['document_name']}"}
                )
            except Exception as e:
                return jsonify({'success': False, 'message': f'Error reading file: {str(e)}'}), 500
        else:
            # For non-image files, return as download
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                return Response(
                    file_content,
                    mimetype="application/octet-stream",
                    headers={"Content-Disposition": f"attachment;filename={document['document_name']}"}
                )
            except Exception as e:
                return jsonify({'success': False, 'message': f'Error reading file: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@require_role('super_admin', 'health_officer')
def delete_document(doc_id):
    """Delete document"""
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
        document = cursor.fetchone()
        
        if not document:
            db.close()
            return jsonify({'success': False, 'message': 'Document not found'}), 404
        
        # Delete file from disk
        file_path = document['file_path']
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete from database
        cursor.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        db.commit()
        
        log_audit("DELETE_DOCUMENT", "documents", doc_id, 
                 {'document': document['document_name']}, {})
        
        db.close()
        
        return jsonify({
            'success': True,
            'message': f'Document deleted successfully'
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route("/documents/<int:doc_id>/verify", methods=["POST"])
@require_role('super_admin')
def verify_document(doc_id):
    """Verify document (admin only)"""
    db = get_db_connection()
    if not db:
        return jsonify({'success': False, 'message': 'Database error'}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("""
            UPDATE documents 
            SET is_verified = 1, verified_by = ?, verified_at = ?
            WHERE id = ?
        """, (session.get('user_id'), datetime.now().isoformat(), doc_id))
        
        db.commit()
        log_audit("VERIFY_DOCUMENT", "documents", doc_id, {}, {'verified': True})
        db.close()
        
        return jsonify({
            'success': True,
            'message': 'Document verified'
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ---------------------- CLINIC VISIT ROUTES ---------------------- #

@app.route("/clinic-visit", methods=["GET", "POST"])
@require_role('super_admin', 'health_officer')
def clinic_visit():
    """Record a clinic visit"""
    if request.method == "GET":
        db = get_db_connection()
        if not db:
            flash("Database error.", "danger")
            return redirect(url_for("dashboard"))
        
        try:
            cursor = db.cursor()
            cursor.execute("SELECT id, name, studentLRN, class FROM students ORDER BY name")
            students = [dict(row) for row in cursor.fetchall()]
            cursor.execute("SELECT id, name, teacherID, department FROM teachers ORDER BY name")
            teachers = [dict(row) for row in cursor.fetchall()]
            db.close()
            
            return render_template("clinic/clinic_visits_list.html", students=students, teachers=teachers)
        except sqlite3.Error as e:
            flash(f"Database error: {str(e)}", "danger")
            return redirect(url_for("dashboard"))
    
    # POST request - save clinic visit
    elif request.method == "POST":
        db = get_db_connection()
        if not db:
            flash("Database error.", "danger")
            return redirect(url_for("clinic_visit"))
        
        try:
            cursor = db.cursor()
            
            # Extract form data
            person_type = request.form.get('person_type')
            person_id = request.form.get('person_id')
            visit_date = request.form.get('visit_date')
            visit_time = request.form.get('visit_time')
            nurse_name = request.form.get('nurse_name', '')
            patient_sex = request.form.get('patient_sex', '')
            patient_age = request.form.get('patient_age') or None
            
            # Vital signs
            temperature = request.form.get('temperature') or None
            blood_pressure = request.form.get('blood_pressure', '')
            heart_rate = request.form.get('heart_rate') or None
            respiratory_rate = request.form.get('respiratory_rate') or None
            
            # Chief complaint
            chief_complaint = request.form.get('chief_complaint', '')
            
            # Physical examination
            physical_examination = request.form.get('physical_examination', '')
            
            # Diagnosis/Assessment
            diagnosis = request.form.get('diagnosis', '')
            assessment = request.form.get('assessment', '')
            
            # Treatment
            treatment_provided = request.form.get('treatment_provided', '')
            medications_given = request.form.get('medications_given', '')
            first_aid_provided = request.form.get('first_aid_provided', '')
            recommendations = request.form.get('recommendations', '')
            
            # Referral
            referral_needed = request.form.get('referral_needed', 0)
            referral_type = request.form.get('referral_type', '') if referral_needed == '1' else ''
            referral_to = request.form.get('referral_to', '') if referral_needed == '1' else ''
            
            # Follow-up
            follow_up_required = request.form.get('follow_up_required', 0)
            follow_up_date = request.form.get('follow_up_date', '') if follow_up_required == '1' else None
            
            # Notes
            visit_notes = request.form.get('visit_notes', '')
            
            # Encrypt sensitive fields
            if encryption_handler:
                try:
                    if physical_examination:
                        physical_examination = encryption_handler.encrypt(physical_examination)
                    if diagnosis:
                        diagnosis = encryption_handler.encrypt(diagnosis)
                    if assessment:
                        assessment = encryption_handler.encrypt(assessment)
                    if medications_given:
                        medications_given = encryption_handler.encrypt(medications_given)
                    if recommendations:
                        recommendations = encryption_handler.encrypt(recommendations)
                except Exception as e:
                    print(f"Encryption error in clinic visit: {e}")
                    flash(f"Warning: Could not encrypt sensitive fields.", "warning")
            
            # Insert into database
            cursor.execute("""
                INSERT INTO clinic_visits (
                    person_type, person_id, visit_date, visit_time, nurse_name, patient_sex, patient_age,
                    temperature, blood_pressure, heart_rate, respiratory_rate,
                    chief_complaint, physical_examination, diagnosis, assessment,
                    treatment_provided, medications_given, first_aid_provided, recommendations,
                    referral_needed, referral_type, referral_to,
                    follow_up_required, follow_up_date, visit_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                person_type, person_id, visit_date, visit_time, nurse_name, patient_sex, patient_age,
                temperature, blood_pressure, heart_rate, respiratory_rate,
                chief_complaint, physical_examination, diagnosis, assessment,
                treatment_provided, medications_given, first_aid_provided, recommendations,
                referral_needed, referral_type, referral_to,
                follow_up_required, follow_up_date, visit_notes
            ))
            
            db.commit()
            db.close()
            
            flash("✓ Clinic visit record saved successfully!", "success")
            return redirect(url_for("view_clinic_visits"))
        except sqlite3.Error as e:
            flash(f"Database error: {str(e)}", "danger")
            return redirect(url_for("clinic_visit"))

# ---------------------- API ENDPOINTS FOR CLINIC VISIT MODAL ---------------------- #

@app.route("/api/students")
def api_get_students():
    """API endpoint to get all students for clinic visit modal"""
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    db = get_db_connection()
    try:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, name, studentLRN, class
            FROM students
            ORDER BY name
        """)
        students = cursor.fetchall()
        db.close()
        
        student_list = []
        for student in students:
            student_list.append({
                'id': safe_row_get(student, 'id'),
                'name': safe_row_get(student, 'name'),
                'studentLRN': safe_row_get(student, 'studentLRN'),
                'class': safe_row_get(student, 'class')
            })
        
        return jsonify({"success": True, "students": student_list})
    except sqlite3.Error as e:
        db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/teachers")
def api_get_teachers():
    """API endpoint to get all teachers for clinic visit modal"""
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    db = get_db_connection()
    try:
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, name, teacherID, department
            FROM teachers
            ORDER BY name
        """)
        teachers = cursor.fetchall()
        db.close()
        
        teacher_list = []
        for teacher in teachers:
            teacher_list.append({
                'id': safe_row_get(teacher, 'id'),
                'name': safe_row_get(teacher, 'name'),
                'teacherID': safe_row_get(teacher, 'teacherID'),
                'department': safe_row_get(teacher, 'department')
            })
        
        return jsonify({"success": True, "teachers": teacher_list})
    except sqlite3.Error as e:
        db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/clinic-visits")
@require_role('super_admin', 'health_officer', 'class_advisor')
def view_clinic_visits():
    """View clinic visits - filtered by role and advisory class for class advisors"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get current user's role and advisory class
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (session.get("user_id"),))
        user_row = cursor.fetchone()
        user_role = safe_row_get(user_row, 'role') if user_row else None
        advisory_class = safe_row_get(user_row, 'advisory_class') if user_row else None
        
        # Build query based on user role
        if user_role == 'class_advisor' and advisory_class:
            # Class advisors only see clinic visits for students in their advisory class
            query = """
                SELECT cv.*, 
                       CASE WHEN cv.person_type = 'student' THEN s.name ELSE t.name END as person_name,
                       CASE WHEN cv.person_type = 'student' THEN s.studentLRN ELSE t.teacherID END as person_code,
                       CASE WHEN cv.person_type = 'student' THEN s.class ELSE NULL END as person_class
                FROM clinic_visits cv
                LEFT JOIN students s ON cv.person_type = 'student' AND cv.person_id = s.id
                LEFT JOIN teachers t ON cv.person_type = 'teacher' AND cv.person_id = t.id
                WHERE cv.person_type = 'student' AND s.class = ?
                ORDER BY cv.visit_date DESC, cv.visit_time DESC
            """
            cursor.execute(query, (advisory_class,))
        else:
            # Admin and health officers see all clinic visits
            query = """
                SELECT cv.*, 
                       CASE WHEN cv.person_type = 'student' THEN s.name ELSE t.name END as person_name,
                       CASE WHEN cv.person_type = 'student' THEN s.studentLRN ELSE t.teacherID END as person_code
                FROM clinic_visits cv
                LEFT JOIN students s ON cv.person_type = 'student' AND cv.person_id = s.id
                LEFT JOIN teachers t ON cv.person_type = 'teacher' AND cv.person_id = t.id
                ORDER BY cv.visit_date DESC, cv.visit_time DESC
            """
            cursor.execute(query)
        
        visits = [decrypt_clinic_visit_record(dict(row)) for row in cursor.fetchall()]
        db.close()
        
        # Add user role context to template
        return render_template("clinic/clinic_visits_list.html", visits=visits, user_role=user_role, advisory_class=advisory_class)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

@app.route("/clinic-visit/<int:visit_id>")
def view_clinic_visit(visit_id):
    """View a specific clinic visit - with role-based access control"""
    if not session.get("logged_in"):
        flash("Please login first.", "danger")
        return redirect(url_for("login"))
    
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get current user's role and advisory class
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (session.get("user_id"),))
        user_row = cursor.fetchone()
        user_role = safe_row_get(user_row, 'role') if user_row else None
        advisory_class = safe_row_get(user_row, 'advisory_class') if user_row else None
        
        cursor.execute("""
            SELECT cv.*, 
                   CASE WHEN cv.person_type = 'student' THEN s.name ELSE t.name END as person_name,
                   CASE WHEN cv.person_type = 'student' THEN s.studentLRN ELSE t.teacherID END as person_code,
                   CASE WHEN cv.person_type = 'student' THEN s.strand ELSE t.department END as person_strand
            FROM clinic_visits cv
            LEFT JOIN students s ON cv.person_type = 'student' AND cv.person_id = s.id
            LEFT JOIN teachers t ON cv.person_type = 'teacher' AND cv.person_id = t.id
            WHERE cv.id = ?
        """, (visit_id,))
        row = cursor.fetchone()
        visit = decrypt_clinic_visit_record(dict(row)) if row else None
        db.close()
        
        if not visit:
            flash("Clinic visit not found.", "danger")
            return redirect(url_for("view_clinic_visits"))
        
        # Access control: Check if class advisor is viewing a visit from their section
        if user_role == 'class_advisor' and advisory_class:
            if visit.get('person_type') == 'student':
                # Verify the student is in their advisory class
                db = get_db_connection()
                cursor = db.cursor()
                cursor.execute("SELECT class FROM students WHERE id = ?", (visit.get('person_id'),))
                student_row = cursor.fetchone()
                db.close()
                
                if student_row:
                    student_class = dict(student_row).get('class')
                    if student_class != advisory_class:
                        flash("You don't have permission to view this clinic visit.", "danger")
                        return redirect(url_for("view_clinic_visits"))
                else:
                    flash("Student not found.", "danger")
                    return redirect(url_for("view_clinic_visits"))
            elif visit.get('person_type') == 'teacher':
                # Class advisors cannot view teacher clinic visits
                flash("You don't have permission to view this clinic visit.", "danger")
                return redirect(url_for("view_clinic_visits"))
        elif user_role not in ['super_admin', 'health_officer']:
            # Only admin, health officer, and class advisors can view clinic visits
            flash("You don't have permission to view clinic visits.", "danger")
            return redirect(url_for("dashboard"))
        
        return render_template("clinic/clinic_visit_detail.html", visit=visit)
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("view_clinic_visits"))

@app.route("/api/clinic-visit/<int:visit_id>", methods=["GET"])
@require_role('super_admin', 'health_officer', 'class_advisor')
def get_clinic_visit_data(visit_id):
    """Get clinic visit data as JSON for modal"""
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        
        # Get current user's role and advisory class
        cursor.execute("SELECT role, advisory_class FROM users WHERE id = ?", (session.get("user_id"),))
        user_row = cursor.fetchone()
        user_role = safe_row_get(user_row, 'role') if user_row else None
        advisory_class = safe_row_get(user_row, 'advisory_class') if user_row else None
        
        # Get the visit record
        cursor.execute("""
            SELECT cv.*, 
                   CASE WHEN cv.person_type = 'student' THEN s.name ELSE t.name END as person_name,
                   CASE WHEN cv.person_type = 'student' THEN s.studentLRN ELSE t.teacherID END as person_code,
                   CASE WHEN cv.person_type = 'student' THEN s.class ELSE t.department END as person_class
            FROM clinic_visits cv
            LEFT JOIN students s ON cv.person_type = 'student' AND cv.person_id = s.id
            LEFT JOIN teachers t ON cv.person_type = 'teacher' AND cv.person_id = t.id
            WHERE cv.id = ?
        """, (visit_id,))
        row = cursor.fetchone()
        visit = decrypt_clinic_visit_record(dict(row)) if row else None
        db.close()
        
        if not visit:
            return jsonify({"success": False, "message": "Clinic visit not found"}), 404
        
        # Check access control for class advisors
        if user_role == 'class_advisor':
            # Class advisors can only access student records from their advisory class
            if visit.get('person_type') == 'teacher':
                return jsonify({"success": False, "message": "Access denied"}), 403
            if visit.get('person_type') == 'student' and visit.get('person_class') != advisory_class:
                return jsonify({"success": False, "message": "Access denied"}), 403
        
        return jsonify({"success": True, "visit": visit})
    except sqlite3.Error as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/clinic-visit/<int:visit_id>/delete", methods=["POST"])
@require_role('super_admin', 'health_officer')
def delete_clinic_visit(visit_id):
    """Delete a clinic visit record"""
    db = get_db_connection()
    if not db:
        if request.is_json:
            return jsonify({"success": False, "message": "Database error"}), 500
        flash("Database error.", "danger")
        return redirect(url_for("view_clinic_visits"))
    
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM clinic_visits WHERE id = ?", (visit_id,))
        db.commit()
        db.close()
        
        # Return JSON for AJAX requests
        if request.is_json:
            return jsonify({"success": True, "message": "Clinic visit deleted successfully"}), 200
        
        # Redirect for regular form submissions
        flash("✓ Clinic visit record deleted successfully!", "success")
        return redirect(url_for("view_clinic_visits"))
    except sqlite3.Error as e:
        if request.is_json:
            return jsonify({"success": False, "message": str(e)}), 500
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("view_clinic_visits"))


# ---------------------- CLINIC REPORTS ---------------------- #

@app.route("/clinic-reports")
@require_role('super_admin', 'health_officer')
def clinic_reports():
    """Generate clinic visit reports"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get filter parameters
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        person_type = request.args.get('person_type', '')
        
        # Build query based on filters
        query = """
            SELECT cv.*,
                   CASE WHEN cv.person_type = 'student' THEN s.name ELSE t.name END as person_name,
                   CASE WHEN cv.person_type = 'student' THEN s.class ELSE t.department END as grade_section,
                   CASE WHEN cv.person_type = 'student' THEN s.id ELSE t.id END as person_id
            FROM clinic_visits cv
            LEFT JOIN students s ON cv.person_type = 'student' AND cv.person_id = s.id
            LEFT JOIN teachers t ON cv.person_type = 'teacher' AND cv.person_id = t.id
            WHERE 1=1
        """
        params = []
        
        # Add date filter
        if start_date:
            query += " AND cv.visit_date >= ?"
            params.append(start_date)
        
        if end_date:
            query += " AND cv.visit_date <= ?"
            params.append(end_date)
        
        # Add person type filter
        if person_type in ['student', 'teacher']:
            query += " AND cv.person_type = ?"
            params.append(person_type)
        
        query += " ORDER BY cv.visit_date DESC, cv.visit_time DESC"
        
        cursor.execute(query, params)
        raw_visits = cursor.fetchall()
        
        # Decrypt visit records
        visits = []
        for row in raw_visits:
            visit = decrypt_clinic_visit_record(dict(row))
            visits.append(visit)
        
        # Calculate statistics
        total_visits = len(visits)
        student_visits = len([v for v in visits if v.get('person_type') == 'student'])
        teacher_visits = len([v for v in visits if v.get('person_type') == 'teacher'])
        followup_required = len([v for v in visits if v.get('followup_required')])
        
        db.close()
        
        return render_template(
            "admin/clinic_report.html",
            visits=visits,
            start_date=start_date,
            end_date=end_date,
            person_type=person_type,
            total_visits=total_visits,
            student_visits=student_visits,
            teacher_visits=teacher_visits,
            followup_required=followup_required,
            school_name="Luis Y. Ferrer Jr. Senior High School"
        )
    
    except sqlite3.Error as e:
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

# ---------------------- BMI MANAGEMENT ---------------------- #

@app.route("/bmi-management")
@require_role('super_admin', 'health_officer')
def bmi_management():
    """View all BMI records organized by section and semester"""
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # If class advisor, only show records for their section
        if user_role == 'class_advisor':
            cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            advisory_class = safe_row_get(user, 'advisory_class')
            
            if not advisory_class:
                db.close()
                flash("You have not been assigned an advisory class.", "danger")
                return redirect(url_for("dashboard"))
            
            cursor.execute("""
                SELECT * FROM bmi_records 
                WHERE section = ?
                ORDER BY section ASC, semester ASC, record_date DESC
            """, (advisory_class,))
        else:
            # For admin/health officer - get all records
            cursor.execute("""
                SELECT * FROM bmi_records 
                ORDER BY section ASC, semester ASC, record_date DESC
            """)
        
        all_records = cursor.fetchall()
        db.close()
        
        # Organize records by section and semester
        organized_records = {}
        for record in all_records:
            section = safe_row_get(record, 'section', 'Unknown')
            semester = safe_row_get(record, 'semester', '1st Semester')
            
            if section not in organized_records:
                organized_records[section] = {}
            
            if semester not in organized_records[section]:
                organized_records[section][semester] = []
            
            organized_records[section][semester].append(record)
        
        response = render_template("admin/bmi_management.html", 
                                 organized_records=organized_records,
                                 all_records=all_records)
        resp = Response(response)
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    except sqlite3.Error as e:
        flash(f"Error loading BMI records: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("dashboard"))

@app.route("/bmi-add", methods=["GET", "POST"])
@require_role('super_admin', 'health_officer')
def bmi_add():
    """Add new BMI record"""
    if request.method == "POST":
        try:
            person_type = request.form.get("person_type", "").strip()
            person_id = request.form.get("person_id", "").strip()
            record_date = request.form.get("record_date", "").strip()
            name = request.form.get("name", "").strip()
            birthdate = request.form.get("birthdate", "").strip()
            grade = request.form.get("grade", "").strip()
            section = request.form.get("section", "").strip()
            height = request.form.get("height", "").strip()
            weight = request.form.get("weight", "").strip()
            nutritional_status = request.form.get("nutritional_status", "").strip()
            height_for_age = request.form.get("height_for_age", "").strip()
            remarks = request.form.get("remarks", "").strip()
            
            # Validate required fields - person_id (LRN) is now required
            if not all([person_type, person_id, name, record_date, height, weight]):
                return jsonify({"success": False, "message": "Please fill in all required fields (Person Type, LRN, Name, Record Date, Height, Weight)."}), 400
            
            try:
                height = float(height)
                weight = float(weight)
            except ValueError:
                return jsonify({"success": False, "message": "Height and weight must be valid numbers."}), 400
            
            # Calculate BMI and category - 6 Tier System
            if height > 0:
                bmi = weight / (height * height)
                if bmi < 15:
                    bmi_category = "Severely wasted"
                elif bmi < 18.5:
                    bmi_category = "Wasted"
                elif bmi < 25:
                    bmi_category = "Normal"
                elif bmi < 30:
                    bmi_category = "Overweight"
                elif bmi <= 40:
                    bmi_category = "Obese"
                else:
                    bmi_category = "Morbidly Obese"
            else:
                bmi = None
                bmi_category = None
            
            db = get_db_connection()
            if not db:
                return jsonify({"success": False, "message": "Database connection error"}), 500
            
            cursor = db.cursor()
            user_id = session.get("user_id")
            
            cursor.execute("""
                INSERT INTO bmi_records 
                (person_type, person_id, record_date, name, birthdate, grade, section, 
                 height, weight, bmi, bmi_category, nutritional_status, height_for_age, 
                 remarks, recorded_by, recorded_by_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (person_type, person_id, record_date, name, birthdate or None, grade, section, 
                  height, weight, bmi, bmi_category, nutritional_status, height_for_age, 
                  remarks, user_id, session.get("username")))
            
            db.commit()
            db.close()
            
            log_audit("CREATE", "bmi_records", cursor.lastrowid, {}, 
                     {"name": name, "bmi": bmi, "bmi_category": bmi_category})
            
            return jsonify({"success": True, "message": "BMI record added successfully!"}), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500
    
    return render_template("admin/bmi_add.html")

@app.route("/bmi-edit/<int:record_id>", methods=["GET", "POST"])
@require_role('super_admin', 'health_officer')
def bmi_edit(record_id):
    """Edit BMI record"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("bmi_management"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bmi_records WHERE id = ?", (record_id,))
        bmi_record = cursor.fetchone()
        
        if not bmi_record:
            db.close()
            flash("BMI record not found.", "danger")
            return redirect(url_for("bmi_management"))
        
        if request.method == "POST":
            record_date = request.form.get("record_date", "").strip()
            name = request.form.get("name", "").strip()
            birthdate = request.form.get("birthdate", "").strip()
            grade = request.form.get("grade", "").strip()
            section = request.form.get("section", "").strip()
            height = request.form.get("height", "").strip()
            weight = request.form.get("weight", "").strip()
            nutritional_status = request.form.get("nutritional_status", "").strip()
            height_for_age = request.form.get("height_for_age", "").strip()
            remarks = request.form.get("remarks", "").strip()
            
            if not all([name, record_date, height, weight]):
                flash("Please fill in all required fields.", "danger")
                return render_template("admin/bmi_edit.html", bmi_record=bmi_record)
            
            try:
                height = float(height)
                weight = float(weight)
            except ValueError:
                flash("Height and weight must be valid numbers.", "danger")
                return render_template("admin/bmi_edit.html", bmi_record=bmi_record)
            
            # Calculate BMI and category
            if height > 0:
                bmi = weight / (height * height)
                if bmi < 18.5:
                    bmi_category = "Underweight"
                elif bmi < 25:
                    bmi_category = "Normal"
                elif bmi < 30:
                    bmi_category = "Overweight"
                else:
                    bmi_category = "Obese"
            else:
                bmi = None
                bmi_category = None
            
            cursor.execute("""
                UPDATE bmi_records 
                SET record_date = ?, name = ?, birthdate = ?, grade = ?, section = ?,
                    height = ?, weight = ?, bmi = ?, bmi_category = ?,
                    nutritional_status = ?, height_for_age = ?, remarks = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (record_date, name, birthdate or None, grade, section, height, weight, 
                  bmi, bmi_category, nutritional_status, height_for_age, remarks, record_id))
            
            db.commit()
            db.close()
            
            log_audit("UPDATE", "bmi_records", record_id, dict(bmi_record),
                     {"name": name, "bmi": bmi, "bmi_category": bmi_category})
            
            flash("BMI record updated successfully!", "success")
            return redirect(url_for("bmi_management"))
        
        db.close()
        return render_template("admin/bmi_edit.html", bmi_record=bmi_record)
    except sqlite3.Error as e:
        if db:
            db.close()
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("bmi_management"))

@app.route("/bmi-view/<int:record_id>")
@require_role('super_admin', 'health_officer')
def bmi_view(record_id):
    """View BMI record details"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("bmi_management"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bmi_records WHERE id = ?", (record_id,))
        record = cursor.fetchone()
        
        db.close()
        
        if not record:
            flash("BMI record not found.", "danger")
            return redirect(url_for("bmi_management"))
        
        return render_template("admin/bmi_view.html", record=record)
    except sqlite3.Error as e:
        if db:
            db.close()
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("bmi_management"))

@app.route("/bmi-delete/<int:record_id>", methods=["POST"])
@require_role('super_admin', 'health_officer')
def bmi_delete(record_id):
    """Delete BMI record"""
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bmi_records WHERE id = ?", (record_id,))
        bmi_record = cursor.fetchone()
        
        if not bmi_record:
            db.close()
            return jsonify({"success": False, "message": "Record not found"}), 404
        
        cursor.execute("DELETE FROM bmi_records WHERE id = ?", (record_id,))
        db.commit()
        db.close()
        
        log_audit("DELETE", "bmi_records", record_id, dict(bmi_record), {})
        
        return jsonify({"success": True, "message": "BMI record deleted successfully!"}), 200
    except sqlite3.Error as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route("/bmi-print/<int:record_id>")
@require_role('super_admin', 'health_officer')
def bmi_print(record_id):
    """Print BMI record in official format"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("bmi_management"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bmi_records WHERE id = ?", (record_id,))
        bmi_record = cursor.fetchone()
        
        if not bmi_record:
            db.close()
            flash("BMI record not found.", "danger")
            return redirect(url_for("bmi_management"))
        
        db.close()
        
        return render_template("admin/bmi_print.html", bmi_record=bmi_record)
    except sqlite3.Error as e:
        if db:
            db.close()
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("bmi_management"))

@app.route("/bmi-export-csv")
@require_role('super_admin', 'health_officer')
def bmi_export_csv():
    """Export all BMI records to CSV in School Form 8 format"""
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bmi_records ORDER BY record_date DESC, name ASC")
        bmi_records = cursor.fetchall()
        
        # Create CSV output
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "School Form 8 - Learner's Basic Health and Nutrition Report",
            "Luis Y. Ferrer Jr. Senior High Scho0l"
        ])
        writer.writerow([])
        writer.writerow(["School Year: 2023-2024", "District: 11", "Division: GENERAL TRIAS CITY", "Region: N-A"])
        writer.writerow([])
        
        # Column headers
        writer.writerow([
            "No", "LRN", "Learner's Name", "Birthdate", "Age",
            "Weight (kg)", "Height (m)", "Height² (m²)", "BMI (kg/m²)",
            "BMI Category", "Nutritional Status", "Height for Age (HFA)", "Remarks"
        ])
        
        # Data rows
        for idx, record in enumerate(bmi_records, 1):
            height = float(record['height']) if record['height'] else 0
            weight = float(record['weight']) if record['weight'] else 0
            height_squared = height * height if height > 0 else 0
            bmi = weight / height_squared if height_squared > 0 else 0
            
            writer.writerow([
                idx,
                record['person_id'] or '',
                record['name'],
                record['birthdate'] or '',
                '',  # Age - can be calculated from birthdate if needed
                f"{weight:.2f}",
                f"{height:.2f}",
                f"{height_squared:.2f}",
                f"{bmi:.1f}" if bmi > 0 else '',
                record['bmi_category'] or '',
                record['nutritional_status'] or '',
                record['height_for_age'] or '',
                record['remarks'] or ''
            ])
        
        writer.writerow([])
        writer.writerow(["SUMMARY TABLE"])
        writer.writerow([])
        
        # Calculate summary statistics
        male_count = 0
        female_count = 0
        normal_count = 0
        overweight_count = 0
        underweight_count = 0
        obese_count = 0
        stunted_count = 0
        normal_hfa_count = 0
        tall_count = 0
        
        for record in bmi_records:
            if record['bmi_category'] == 'Normal':
                normal_count += 1
            elif record['bmi_category'] == 'Overweight':
                overweight_count += 1
            elif record['bmi_category'] == 'Underweight':
                underweight_count += 1
            elif record['bmi_category'] == 'Obese':
                obese_count += 1
            
            if record['height_for_age'] == 'Stunted':
                stunted_count += 1
            elif record['height_for_age'] == 'Normal':
                normal_hfa_count += 1
            elif record['height_for_age'] == 'Tall':
                tall_count += 1
        
        # Nutritional Status Summary
        writer.writerow(["Nutritional Status Summary Table"])
        writer.writerow(["Underweight", normal_count, "Overweight", overweight_count, "Obese", obese_count])
        writer.writerow(["Count", underweight_count, "Count", normal_count, "Count", len(bmi_records)])
        writer.writerow([])
        
        # Height for Age Summary
        writer.writerow(["Height for Age (HFA) Summary Table"])
        writer.writerow(["Stunted", stunted_count, "Normal", normal_hfa_count, "Tall", tall_count])
        writer.writerow(["Count", stunted_count, "Count", normal_hfa_count, "Count", tall_count])
        writer.writerow([])
        
        # Signature lines
        writer.writerow(["Date of Assessment:", "", "Conducted/Assessed By:", "", "Certified Correct By:", ""])
        writer.writerow(["________________", "", "________________", "", "________________", ""])
        writer.writerow([])
        writer.writerow(["Reviewed By:", "", ""])
        writer.writerow(["________________", "", ""])
        
        db.close()
        
        # Prepare response
        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = f"attachment;filename=bmi_records_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        response.headers["Content-Type"] = "text/csv"
        return response
    
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

# ---------------------- BMI SECTION VIEW ---------------------- #

@app.route("/bmi-section-view")
@require_role('super_admin', 'health_officer')
def bmi_section_view():
    """View and filter BMI records by section with section-based organization"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get distinct sections from BMI records
        cursor.execute("SELECT DISTINCT section FROM bmi_records WHERE section IS NOT NULL AND section != '' ORDER BY section")
        sections_result = cursor.fetchall()
        sections = [row['section'] for row in sections_result]
        
        # Get selected section from query parameter
        selected_section = request.args.get('section', '')
        
        # Get all sections with record counts
        cursor.execute("""
            SELECT section, COUNT(*) as count 
            FROM bmi_records 
            WHERE section IS NOT NULL AND section != ''
            GROUP BY section
            ORDER BY section
        """)
        section_counts = {row['section']: row['count'] for row in cursor.fetchall()}
        
        # Get records for selected section
        bmi_records = []
        if selected_section:
            cursor.execute("""
                SELECT * FROM bmi_records 
                WHERE section = ?
                ORDER BY record_date DESC, name ASC
            """, (selected_section,))
            bmi_records = cursor.fetchall()
        
        db.close()
        
        return render_template("admin/bmi_section_view.html", 
                             sections=sections,
                             section_counts=section_counts,
                             selected_section=selected_section,
                             bmi_records=bmi_records)
    except sqlite3.Error as e:
        flash(f"Error loading BMI records: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("dashboard"))

@app.route("/api/bmi/add", methods=["POST"])
@require_role('super_admin', 'health_officer')
def api_bmi_add():
    """API endpoint to add BMI record via modal"""
    try:
        person_type = request.form.get("person_type", "").strip()
        person_id = request.form.get("person_id", "").strip()
        record_date = request.form.get("record_date", "").strip()
        name = request.form.get("name", "").strip()
        birthdate = request.form.get("birthdate", "").strip()
        grade = request.form.get("grade", "").strip()
        section = request.form.get("section", "").strip()
        semester = request.form.get("semester", "").strip()
        gender = request.form.get("gender", "").strip()
        strand = request.form.get("strand", "").strip()
        height = request.form.get("height", "").strip()
        weight = request.form.get("weight", "").strip()
        nutritional_status = request.form.get("nutritional_status", "").strip()
        height_for_age = request.form.get("height_for_age", "").strip()
        remarks = request.form.get("remarks", "").strip()
        
        # Validate
        if not all([person_type, name, record_date, height, weight, section]):
            return jsonify({"success": False, "message": "All fields are required."}), 400
        
        try:
            height = float(height)
            weight = float(weight)
        except ValueError:
            return jsonify({"success": False, "message": "Height and weight must be numbers."}), 400
        
        # Generate person_id if not provided (format: section-name)
        if not person_id:
            person_id = f"{section}-{name.lower().replace(' ', '_')}"
        
        # Calculate BMI - 6 Tier System
        if height > 0:
            bmi = weight / (height * height)
            if bmi < 15:
                bmi_category = "Severely wasted"
            elif bmi < 18.5:
                bmi_category = "Wasted"
            elif bmi < 25:
                bmi_category = "Normal"
            elif bmi < 30:
                bmi_category = "Overweight"
            elif bmi <= 40:
                bmi_category = "Obese"
            else:
                bmi_category = "Morbidly Obese"
        else:
            bmi = None
            bmi_category = None
        
        db = get_db_connection()
        if not db:
            return jsonify({"success": False, "message": "Database error"}), 500
        
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO bmi_records 
            (person_type, person_id, record_date, name, birthdate, grade, section, semester, gender, strand,
             height, weight, bmi, bmi_category, nutritional_status, height_for_age, 
             remarks, recorded_by, recorded_by_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (person_type, person_id, record_date, name, birthdate or None, grade, section, semester, gender, strand,
              height, weight, bmi, bmi_category, nutritional_status, height_for_age, 
              remarks, session.get("user_id"), session.get("username")))
        
        db.commit()
        record_id = cursor.lastrowid
        db.close()
        
        log_audit("CREATE", "bmi_records", record_id, {}, 
                 {"name": name, "section": section, "semester": semester, "bmi": bmi})
        
        return jsonify({"success": True, "message": "BMI record added!", "record_id": record_id}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/bmi/edit/<int:record_id>", methods=["POST"])
@require_role('super_admin', 'health_officer')
def api_bmi_edit(record_id):
    """API endpoint to edit BMI record via modal"""
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bmi_records WHERE id = ?", (record_id,))
        old_record = cursor.fetchone()
        
        if not old_record:
            db.close()
            return jsonify({"success": False, "message": "Record not found"}), 404
        
        record_date = request.form.get("record_date", "").strip()
        name = request.form.get("name", "").strip()
        birthdate = request.form.get("birthdate", "").strip()
        grade = request.form.get("grade", "").strip()
        section = request.form.get("section", "").strip()
        semester = request.form.get("semester", "").strip()
        gender = request.form.get("gender", "").strip()
        strand = request.form.get("strand", "").strip()
        height = request.form.get("height", "").strip()
        weight = request.form.get("weight", "").strip()
        nutritional_status = request.form.get("nutritional_status", "").strip()
        height_for_age = request.form.get("height_for_age", "").strip()
        remarks = request.form.get("remarks", "").strip()
        
        if not all([name, record_date, height, weight, section]):
            db.close()
            return jsonify({"success": False, "message": "All fields required"}), 400
        
        try:
            height = float(height)
            weight = float(weight)
        except ValueError:
            db.close()
            return jsonify({"success": False, "message": "Invalid numbers"}), 400
        
        # Calculate BMI - 6 Tier System
        if height > 0:
            bmi = weight / (height * height)
            if bmi < 15:
                bmi_category = "Severely wasted"
            elif bmi < 18.5:
                bmi_category = "Wasted"
            elif bmi < 25:
                bmi_category = "Normal"
            elif bmi < 30:
                bmi_category = "Overweight"
            elif bmi <= 40:
                bmi_category = "Obese"
            else:
                bmi_category = "Morbidly Obese"
        else:
            bmi = None
            bmi_category = None
        
        cursor.execute("""
            UPDATE bmi_records 
            SET record_date = ?, name = ?, birthdate = ?, grade = ?, section = ?, semester = ?,
                gender = ?, strand = ?, height = ?, weight = ?, bmi = ?, bmi_category = ?,
                nutritional_status = ?, height_for_age = ?, remarks = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (record_date, name, birthdate or None, grade, section, semester, gender, strand, height, weight, 
              bmi, bmi_category, nutritional_status, height_for_age, remarks, record_id))
        
        db.commit()
        db.close()
        
        log_audit("UPDATE", "bmi_records", record_id, dict(old_record),
                 {"name": name, "section": section, "semester": semester, "bmi": bmi})
        
        return jsonify({"success": True, "message": "Record updated!"}), 200
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/bmi/delete/<int:record_id>", methods=["DELETE"])
@require_role('super_admin', 'health_officer')
def api_bmi_delete(record_id):
    """API endpoint to delete BMI record via modal"""
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bmi_records WHERE id = ?", (record_id,))
        record = cursor.fetchone()
        
        if not record:
            db.close()
            return jsonify({"success": False, "message": "Not found"}), 404
        
        cursor.execute("DELETE FROM bmi_records WHERE id = ?", (record_id,))
        db.commit()
        db.close()
        
        log_audit("DELETE", "bmi_records", record_id, dict(record), {})
        
        return jsonify({"success": True, "message": "Record deleted!"}), 200
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/bmi/<int:record_id>")
@require_role('super_admin', 'health_officer')
def api_get_bmi_record(record_id):
    """Get BMI record data for modal"""
    db = None
    try:
        db = get_db_connection()
        if not db:
            return jsonify({"success": False, "message": "Database error"}), 500
        
        cursor = db.cursor()
        cursor.execute("SELECT * FROM bmi_records WHERE id = ?", (record_id,))
        record = cursor.fetchone()
        db.close()
        
        if not record:
            return jsonify({"success": False, "message": "Not found"}), 404
        
        record_dict = dict(record)
        
        # Calculate BMI if height and weight are available
        if record_dict.get('height') and record_dict.get('weight'):
            height = float(record_dict['height'])
            weight = float(record_dict['weight'])
            bmi = weight / (height * height)
            
            # Classify BMI - 6 Tier System
            if bmi < 15:
                record_dict['nutritional_status'] = 'Severely wasted'
            elif bmi < 18.5:
                record_dict['nutritional_status'] = 'Wasted'
            elif bmi < 25:
                record_dict['nutritional_status'] = 'Normal'
            elif bmi < 30:
                record_dict['nutritional_status'] = 'Overweight'
            elif bmi <= 40:
                record_dict['nutritional_status'] = 'Obese'
            else:
                record_dict['nutritional_status'] = 'Morbidly Obese'
            
            # Calculate Height for Age if DOB is available
            if record_dict.get('birthdate') and record_dict.get('record_date'):
                from datetime import datetime
                try:
                    birthdate = datetime.strptime(record_dict['birthdate'], '%Y-%m-%d')
                    record_date = datetime.strptime(record_dict['record_date'], '%Y-%m-%d')
                    
                    age_in_months = (record_date.year - birthdate.year) * 12
                    age_in_months += record_date.month - birthdate.month
                    if record_date.day < birthdate.day:
                        age_in_months -= 1
                    
                    age_in_years = age_in_months / 12
                    age = int(age_in_years)
                    
                    # WHO/CDC Height-for-Age Standards
                    standards = {
                        6: 1.14, 7: 1.20, 8: 1.26, 9: 1.31, 10: 1.37,
                        11: 1.43, 12: 1.49, 13: 1.55, 14: 1.61, 15: 1.66,
                        16: 1.70, 17: 1.73, 18: 1.75
                    }
                    
                    if 6 <= age <= 18:
                        expected_height = standards.get(age, 1.75)
                        stunting_threshold = expected_height * 0.9
                        record_dict['height_for_age'] = 'Stunted' if height < stunting_threshold else 'Normal'
                    else:
                        record_dict['height_for_age'] = 'N/A'
                except:
                    record_dict['height_for_age'] = 'N/A'
        
        return jsonify({"success": True, "record": record_dict})
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route("/bmi-section-print/<section>")
@require_role('super_admin', 'health_officer')
def bmi_section_print(section):
    """Print BMI records for a specific section"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("bmi_section_view"))
    
    try:
        cursor = db.cursor()
        cursor.execute("""
            SELECT * FROM bmi_records 
            WHERE section = ?
            ORDER BY record_date DESC, name ASC
        """, (section,))
        bmi_records = cursor.fetchall()
        db.close()
        
        return render_template("admin/bmi_section_print.html", 
                             section=section, 
                             bmi_records=bmi_records)
    except sqlite3.Error as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("bmi_section_view"))

# ---------------------- DEWORMING MANAGEMENT ---------------------- #

@app.route("/deworming-management")
@require_role('super_admin', 'health_officer')
def deworming_management():
    """List all deworming records"""
    user_role = session.get('role')
    user_id = session.get('user_id')
    
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # If class advisor, only show records for their section
        if user_role == 'class_advisor':
            cursor.execute("SELECT advisory_class FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            advisory_class = safe_row_get(user, 'advisory_class')
            
            if not advisory_class:
                db.close()
                flash("You have not been assigned an advisory class.", "danger")
                return redirect(url_for("dashboard"))
            
            cursor.execute("""
                SELECT * FROM deworming_records 
                WHERE section = ?
                ORDER BY recorded_date DESC, name ASC
            """, (advisory_class,))
        else:
            cursor.execute("""
                SELECT * FROM deworming_records 
                ORDER BY recorded_date DESC, name ASC
            """)
        
        deworming_records = cursor.fetchall()
        db.close()
        
        return render_template("admin/deworming_management.html", deworming_records=deworming_records)
    except sqlite3.Error as e:
        flash(f"Error loading deworming records: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("dashboard"))

@app.route("/deworming-add", methods=["GET", "POST"])
@require_role('super_admin', 'health_officer')
def deworming_add():
    """Add new deworming record"""
    if request.method == "POST":
        person_type = request.form.get("person_type", "").strip()
        person_id = request.form.get("person_id", "").strip()
        name = request.form.get("name", "").strip()
        grade = request.form.get("grade", "").strip()
        section = request.form.get("section", "").strip()
        lrn = request.form.get("lrn", "").strip()
        school_year = request.form.get("school_year", "").strip()
        recorded_date = request.form.get("recorded_date", "").strip()
        
        pre_4ps_recipient = request.form.get("pre_4ps_recipient", "").strip()
        pre_4ps_with_consent = request.form.get("pre_4ps_with_consent", "").strip()
        pre_non_4ps_consent = request.form.get("pre_non_4ps_consent", "").strip()
        pre_deworming_consent = request.form.get("pre_deworming_consent", "").strip()
        
        post_4ps_children = request.form.get("post_4ps_children", "").strip()
        post_non_4ps_children = request.form.get("post_non_4ps_children", "").strip()
        post_serious_illness = request.form.get("post_serious_illness", "").strip()
        post_adverse_effect = request.form.get("post_adverse_effect", "").strip()
        
        remarks = request.form.get("remarks", "").strip()
        
        if not all([person_type, name, section, recorded_date]):
            flash("Please fill in all required fields.", "danger")
            return render_template("admin/deworming_add.html")
        
        db = get_db_connection()
        if not db:
            flash("Database error.", "danger")
            return redirect(url_for("deworming_management"))
        
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO deworming_records 
            (person_type, person_id, name, grade, section, lrn, school_year, 
             pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent, pre_deworming_consent,
             post_4ps_children, post_non_4ps_children, post_serious_illness, post_adverse_effect,
             remarks, recorded_date, recorded_by, recorded_by_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (person_type, person_id or None, name, grade, section, lrn, school_year,
              pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent, pre_deworming_consent,
              post_4ps_children, post_non_4ps_children, post_serious_illness, post_adverse_effect,
              remarks, recorded_date, session.get("user_id"), session.get("username")))
        
        db.commit()
        record_id = cursor.lastrowid
        db.close()
        
        log_audit("CREATE", "deworming_records", record_id, {}, 
                 {"name": name, "section": section})
        
        flash("Deworming record added successfully!", "success")
        return redirect(url_for("deworming_management"))
    
    return render_template("admin/deworming_add.html")

@app.route("/deworming-edit/<int:record_id>", methods=["GET", "POST"])
@require_role('super_admin', 'health_officer')
def deworming_edit(record_id):
    """Edit deworming record"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("deworming_management"))
    
    cursor = db.cursor()
    cursor.execute("SELECT * FROM deworming_records WHERE id = ?", (record_id,))
    deworming_record = cursor.fetchone()
    
    if not deworming_record:
        db.close()
        flash("Record not found.", "danger")
        return redirect(url_for("deworming_management"))
    
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        grade = request.form.get("grade", "").strip()
        section = request.form.get("section", "").strip()
        lrn = request.form.get("lrn", "").strip()
        school_year = request.form.get("school_year", "").strip()
        recorded_date = request.form.get("recorded_date", "").strip()
        
        pre_4ps_recipient = request.form.get("pre_4ps_recipient", "").strip()
        pre_4ps_with_consent = request.form.get("pre_4ps_with_consent", "").strip()
        pre_non_4ps_consent = request.form.get("pre_non_4ps_consent", "").strip()
        pre_deworming_consent = request.form.get("pre_deworming_consent", "").strip()
        
        post_4ps_children = request.form.get("post_4ps_children", "").strip()
        post_non_4ps_children = request.form.get("post_non_4ps_children", "").strip()
        post_serious_illness = request.form.get("post_serious_illness", "").strip()
        post_adverse_effect = request.form.get("post_adverse_effect", "").strip()
        
        remarks = request.form.get("remarks", "").strip()
        
        if not all([name, section, recorded_date]):
            flash("Please fill in all required fields.", "danger")
            return render_template("admin/deworming_edit.html", deworming_record=deworming_record)
        
        cursor.execute("""
            UPDATE deworming_records 
            SET name = ?, grade = ?, section = ?, lrn = ?, school_year = ?,
                pre_4ps_recipient = ?, pre_4ps_with_consent = ?, pre_non_4ps_consent = ?, pre_deworming_consent = ?,
                post_4ps_children = ?, post_non_4ps_children = ?, post_serious_illness = ?, post_adverse_effect = ?,
                remarks = ?, recorded_date = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (name, grade, section, lrn, school_year,
              pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent, pre_deworming_consent,
              post_4ps_children, post_non_4ps_children, post_serious_illness, post_adverse_effect,
              remarks, recorded_date, record_id))
        
        db.commit()
        db.close()
        
        log_audit("UPDATE", "deworming_records", record_id, dict(deworming_record),
                 {"name": name, "section": section})
        
        flash("Deworming record updated successfully!", "success")
        return redirect(url_for("deworming_management"))
    
    db.close()
    return render_template("admin/deworming_edit.html", deworming_record=deworming_record)

@app.route("/deworming-delete/<int:record_id>", methods=["POST"])
@require_role('super_admin', 'health_officer')
def deworming_delete(record_id):
    """Delete deworming record"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("deworming_management"))
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM deworming_records WHERE id = ?", (record_id,))
        record = cursor.fetchone()
        
        if not record:
            db.close()
            flash("Record not found.", "danger")
            return redirect(url_for("deworming_management"))
        
        cursor.execute("DELETE FROM deworming_records WHERE id = ?", (record_id,))
        db.commit()
        db.close()
        
        log_audit("DELETE", "deworming_records", record_id, dict(record), {})
        
        flash("Deworming record deleted successfully!", "success")
        return redirect(url_for("deworming_management"))
    except sqlite3.Error as e:
        flash(f"Error: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("deworming_management"))

# ---------------------- DEWORMING SECTION VIEW ---------------------- #

@app.route("/deworming-section-view")
@require_role('super_admin', 'health_officer')
def deworming_section_view():
    """View and filter deworming records by section"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("dashboard"))
    
    try:
        cursor = db.cursor()
        
        # Get distinct sections
        cursor.execute("SELECT DISTINCT section FROM deworming_records WHERE section IS NOT NULL AND section != '' ORDER BY section")
        sections_result = cursor.fetchall()
        sections = [row['section'] for row in sections_result]
        
        # Get selected section
        selected_section = request.args.get('section', '')
        
        # Get all sections with record counts
        cursor.execute("""
            SELECT section, COUNT(*) as count 
            FROM deworming_records 
            WHERE section IS NOT NULL AND section != ''
            GROUP BY section
            ORDER BY section
        """)
        section_counts = {row['section']: row['count'] for row in cursor.fetchall()}
        
        # Get records for selected section
        deworming_records = []
        if selected_section:
            cursor.execute("""
                SELECT * FROM deworming_records 
                WHERE section = ?
                ORDER BY recorded_date DESC, name ASC
            """, (selected_section,))
            deworming_records = cursor.fetchall()
        
        db.close()
        
        return render_template("admin/deworming_section_view.html", 
                             sections=sections,
                             section_counts=section_counts,
                             selected_section=selected_section,
                             deworming_records=deworming_records)
    except sqlite3.Error as e:
        flash(f"Error loading deworming records: {str(e)}", "danger")
        if db:
            db.close()
        return redirect(url_for("dashboard"))

@app.route("/api/deworming/add", methods=["POST"])
@require_role('super_admin', 'health_officer')
def api_deworming_add():
    """API endpoint to add deworming record"""
    try:
        person_type = request.form.get("person_type", "").strip()
        person_id = request.form.get("person_id", "").strip()
        name = request.form.get("name", "").strip()
        grade = request.form.get("grade", "").strip()
        section = request.form.get("section", "").strip()
        gender = request.form.get("gender", "").strip()
        lrn = request.form.get("lrn", "").strip()
        school_year = request.form.get("school_year", "").strip()
        recorded_date = request.form.get("recorded_date", "").strip()
        
        # Pre-deworming fields
        pre_4ps_recipient = request.form.get("pre_4ps_recipient", "").strip()
        pre_4ps_with_consent = request.form.get("pre_4ps_with_consent", "").strip()
        pre_non_4ps_consent = request.form.get("pre_non_4ps_consent", "").strip()
        pre_deworming_consent = request.form.get("pre_deworming_consent", "").strip()
        
        # Post-deworming fields
        post_4ps_children = request.form.get("post_4ps_children", "").strip()
        post_non_4ps_children = request.form.get("post_non_4ps_children", "").strip()
        post_serious_illness = request.form.get("post_serious_illness", "").strip()
        post_adverse_effect = request.form.get("post_adverse_effect", "").strip()
        
        remarks = request.form.get("remarks", "").strip()
        
        if not all([person_type, name, section, recorded_date]):
            return jsonify({"success": False, "message": "Required fields missing"}), 400
        
        # Generate person_id if not provided (format: section-name)
        if not person_id:
            person_id = f"{section}-{name.lower().replace(' ', '_')}"
        
        db = get_db_connection()
        if not db:
            return jsonify({"success": False, "message": "Database error"}), 500
        
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO deworming_records 
            (person_type, person_id, name, grade, section, gender, lrn, school_year, 
             pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent, pre_deworming_consent,
             post_4ps_children, post_non_4ps_children, post_serious_illness, post_adverse_effect,
             remarks, recorded_date, recorded_by, recorded_by_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (person_type, person_id, name, grade, section, gender, lrn, school_year,
              pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent, pre_deworming_consent,
              post_4ps_children, post_non_4ps_children, post_serious_illness, post_adverse_effect,
              remarks, recorded_date, session.get("user_id"), session.get("username")))
        
        db.commit()
        record_id = cursor.lastrowid
        db.close()
        
        log_audit("CREATE", "deworming_records", record_id, {}, 
                 {"name": name, "section": section})
        
        return jsonify({"success": True, "message": "Deworming record added!", "record_id": record_id}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/deworming/edit/<int:record_id>", methods=["POST"])
@require_role('super_admin', 'health_officer')
def api_deworming_edit(record_id):
    """API endpoint to edit deworming record"""
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM deworming_records WHERE id = ?", (record_id,))
        old_record = cursor.fetchone()
        
        if not old_record:
            db.close()
            return jsonify({"success": False, "message": "Record not found"}), 404
        
        name = request.form.get("name", "").strip()
        grade = request.form.get("grade", "").strip()
        section = request.form.get("section", "").strip()
        gender = request.form.get("gender", "").strip()
        lrn = request.form.get("lrn", "").strip()
        school_year = request.form.get("school_year", "").strip()
        recorded_date = request.form.get("recorded_date", "").strip()
        
        pre_4ps_recipient = request.form.get("pre_4ps_recipient", "").strip()
        pre_4ps_with_consent = request.form.get("pre_4ps_with_consent", "").strip()
        pre_non_4ps_consent = request.form.get("pre_non_4ps_consent", "").strip()
        pre_deworming_consent = request.form.get("pre_deworming_consent", "").strip()
        
        post_4ps_children = request.form.get("post_4ps_children", "").strip()
        post_non_4ps_children = request.form.get("post_non_4ps_children", "").strip()
        post_serious_illness = request.form.get("post_serious_illness", "").strip()
        post_adverse_effect = request.form.get("post_adverse_effect", "").strip()
        
        remarks = request.form.get("remarks", "").strip()
        
        if not all([name, section, recorded_date]):
            db.close()
            return jsonify({"success": False, "message": "Required fields missing"}), 400
        
        cursor.execute("""
            UPDATE deworming_records 
            SET name = ?, grade = ?, section = ?, gender = ?, lrn = ?, school_year = ?,
                pre_4ps_recipient = ?, pre_4ps_with_consent = ?, pre_non_4ps_consent = ?, pre_deworming_consent = ?,
                post_4ps_children = ?, post_non_4ps_children = ?, post_serious_illness = ?, post_adverse_effect = ?,
                remarks = ?, recorded_date = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (name, grade, section, gender, lrn, school_year,
              pre_4ps_recipient, pre_4ps_with_consent, pre_non_4ps_consent, pre_deworming_consent,
              post_4ps_children, post_non_4ps_children, post_serious_illness, post_adverse_effect,
              remarks, recorded_date, record_id))
        
        db.commit()
        db.close()
        
        log_audit("UPDATE", "deworming_records", record_id, dict(old_record),
                 {"name": name, "section": section})
        
        return jsonify({"success": True, "message": "Record updated!"}), 200
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/deworming/delete/<int:record_id>", methods=["DELETE"])
@require_role('super_admin', 'health_officer')
def api_deworming_delete(record_id):
    """API endpoint to delete deworming record"""
    db = get_db_connection()
    if not db:
        return jsonify({"success": False, "message": "Database error"}), 500
    
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM deworming_records WHERE id = ?", (record_id,))
        record = cursor.fetchone()
        
        if not record:
            db.close()
            return jsonify({"success": False, "message": "Not found"}), 404
        
        cursor.execute("DELETE FROM deworming_records WHERE id = ?", (record_id,))
        db.commit()
        db.close()
        
        log_audit("DELETE", "deworming_records", record_id, dict(record), {})
        
        return jsonify({"success": True, "message": "Record deleted!"}), 200
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/api/deworming/<int:record_id>")
@require_role('super_admin', 'health_officer')
def api_get_deworming_record(record_id):
    """Get deworming record data for modal"""
    db = None
    try:
        db = get_db_connection()
        if not db:
            return jsonify({"success": False, "message": "Database error"}), 500
        
        cursor = db.cursor()
        cursor.execute("SELECT * FROM deworming_records WHERE id = ?", (record_id,))
        record = cursor.fetchone()
        db.close()
        
        if not record:
            return jsonify({"success": False, "message": "Not found"}), 404
        
        record_dict = dict(record)
        return jsonify({"success": True, "record": record_dict})
    except Exception as e:
        if db:
            db.close()
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@app.route("/deworming-section-print/<section>")
@require_role('super_admin', 'health_officer')
def deworming_section_print(section):
    """Print deworming records for a specific section"""
    db = get_db_connection()
    if not db:
        flash("Database error.", "danger")
        return redirect(url_for("deworming_section_view"))
    
    try:
        cursor = db.cursor()
        cursor.execute("""
            SELECT * FROM deworming_records 
            WHERE section = ?
            ORDER BY recorded_date DESC, name ASC
        """, (section,))
        deworming_records = cursor.fetchall()
        db.close()
        
        return render_template("admin/deworming_section_print.html", 
                             section=section, 
                             deworming_records=deworming_records,
                             now=datetime.now)
    except sqlite3.Error as e:
        flash(f"Error: {str(e)}", "danger")
        return redirect(url_for("deworming_section_view"))

# ---------------------- MAIN ---------------------- #

if __name__ == "__main__":

    app.run(debug=True, host="0.0.0.0", port=5000)
