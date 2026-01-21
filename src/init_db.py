"""
Database Initialization Script
Run this script to create the SQLite database and tables
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os
import bcrypt

# Get project root directory (parent of src/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Database file path
DATABASE = os.path.join(PROJECT_ROOT, 'data', 'student_health.db')
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

def hash_password(password):
    """Hash password using bcrypt with salt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def create_tables():
    """Create all necessary tables"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Create users table for authentication
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                fullname TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'health_officer',
                advisory_class TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create students table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                studentLRN TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                class TEXT,
                strand TEXT,
                section TEXT,
                dob DATE,
                address TEXT,
                parentContact TEXT,
                emergencyContact TEXT,
                height TEXT,
                weight TEXT,
                blood TEXT,
                pastIllnesses TEXT,
                allergies TEXT,
                conditions TEXT,
                vaccination TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create teachers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS teachers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacherID TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                department TEXT,
                dob DATE,
                address TEXT,
                contact TEXT,
                height TEXT,
                weight TEXT,
                blood TEXT,
                pastIllnesses TEXT,
                allergies TEXT,
                conditions TEXT,
                vaccination TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create inventory table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL,
                category TEXT,
                quantity INTEGER DEFAULT 0,
                unit TEXT,
                status TEXT DEFAULT 'available',
                expiry_date DATE,
                reorder_level INTEGER DEFAULT 5,
                supplier TEXT,
                notes TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        
        # Create audit log table for tracking all modifications
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                table_name TEXT NOT NULL,
                record_id INTEGER,
                old_values TEXT,
                new_values TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
    
        
        # Create documents table for sensitive file uploads (personal info, medical records, etc)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_name TEXT NOT NULL,
                document_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER,
                person_type TEXT,
                person_id INTEGER,
                description TEXT,
                sensitivity_level TEXT DEFAULT 'confidential',
                uploaded_by INTEGER NOT NULL,
                uploaded_by_name TEXT,
                is_verified INTEGER DEFAULT 0,
                verified_by INTEGER,
                verified_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(uploaded_by) REFERENCES users(id),
                FOREIGN KEY(verified_by) REFERENCES users(id)
            )
        """)
        
        # Create clinic visit records table for health records
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS clinic_visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_type TEXT NOT NULL,
                person_id INTEGER NOT NULL,
                visit_date DATE NOT NULL,
                visit_time TIME,
                nurse_id INTEGER,
                nurse_name TEXT,
                
                -- Patient Demographics
                patient_sex TEXT,
                patient_age INTEGER,
                
                -- Vital Signs
                temperature REAL,
                blood_pressure TEXT,
                heart_rate INTEGER,
                respiratory_rate INTEGER,
                
                -- Chief Complaint
                chief_complaint TEXT NOT NULL,
                
                -- Physical Examination
                physical_examination TEXT,
                
                -- Diagnosis/Assessment
                diagnosis TEXT,
                assessment TEXT,
                
                -- Treatment
                treatment_provided TEXT,
                medications_given TEXT,
                first_aid_provided TEXT,
                recommendations TEXT,
                
                -- Referral
                referral_needed INTEGER DEFAULT 0,
                referral_type TEXT,
                referral_to TEXT,
                
                -- Additional Notes
                visit_notes TEXT,
                follow_up_required INTEGER DEFAULT 0,
                follow_up_date DATE,
                
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(nurse_id) REFERENCES users(id)
            )
        """)
        
        # Create BMI records table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bmi_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_type TEXT NOT NULL,
                person_id INTEGER NOT NULL,
                record_date DATE NOT NULL,
                name TEXT NOT NULL,
                birthdate DATE,
                grade TEXT,
                section TEXT,
                height REAL NOT NULL,
                weight REAL NOT NULL,
                bmi REAL,
                bmi_category TEXT,
                nutritional_status TEXT,
                height_for_age TEXT,
                remarks TEXT,
                recorded_by INTEGER,
                recorded_by_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(recorded_by) REFERENCES users(id)
            )
        """)
        
        # Create deworming records table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deworming_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_type TEXT NOT NULL,
                person_id TEXT,
                name TEXT NOT NULL,
                grade TEXT,
                section TEXT NOT NULL,
                lrn TEXT,
                school_year TEXT,
                pre_4ps_recipient TEXT,
                pre_4ps_with_consent TEXT,
                pre_non_4ps_consent TEXT,
                pre_deworming_consent TEXT,
                post_4ps_children TEXT,
                post_non_4ps_children TEXT,
                post_serious_illness TEXT,
                post_adverse_effect TEXT,
                remarks TEXT,
                recorded_date TEXT,
                recorded_by INTEGER,
                recorded_by_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(recorded_by) REFERENCES users(id)
            )
        """)
        
        # Create password reset tokens table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                reset_code TEXT NOT NULL UNIQUE,
                is_used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        
        # Reset all data tables - delete sample records (only from tables that exist)
        # NOTE: Only delete on fresh database creation, not on every run
        # Commented out to preserve existing data
        # try:
        #     cursor.execute("DELETE FROM students")
        #     cursor.execute("DELETE FROM teachers")
        #     cursor.execute("DELETE FROM health_records")
        #     cursor.execute("DELETE FROM inventory")
        #     cursor.execute("DELETE FROM health_reminders")
        #     cursor.execute("DELETE FROM audit_log")
        #     cursor.execute("DELETE FROM backup_log")
        # except sqlite3.OperationalError:
        #     pass  # Tables might not exist on first run
        
        # Reset users table and create strong super admin user
        # Only delete existing users if this is a fresh database
        try:
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            if user_count == 0:
                # Fresh database - safe to proceed
                pass
        except sqlite3.OperationalError:
            pass  # Table doesn't exist yet
        
        # Get super admin credentials from environment variables
        # For development, these should be set in .env file
        # For production, set these securely in your deployment environment
        admin_username = os.environ.get('ADMIN_USERNAME')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        admin_fullname = os.environ.get('ADMIN_FULLNAME', 'System Administrator')
        admin_email = os.environ.get('ADMIN_EMAIL')
        
        # Only create super admin if credentials are provided and user doesn't exist
        if admin_username and admin_password and admin_email:
            admin_hashed_password = hash_password(admin_password)
            cursor.execute("SELECT id FROM users WHERE username = ?", (admin_username,))
            if not cursor.fetchone():
                # Create super admin user
                cursor.execute("""
                    INSERT INTO users (username, password, fullname, email, role, is_active)
                    VALUES (?, ?, ?, ?, 'super_admin', 1)
                """, (admin_username, admin_hashed_password, admin_fullname, admin_email))
                print("\nSUPER ADMIN USER CREATED")
                print("="*60)
                print(f"Username: {admin_username}")
                print(f"Email: {admin_email}")
                print("="*60)
                print("IMPORTANT: Save these credentials securely!")
                print("="*60 + "\n")
            else:
                print("\nSUPER ADMIN USER ALREADY EXISTS")
                print("(No new user created to preserve data)\n")
        else:
            print("\nWARNING: Super admin credentials not set in environment variables")
            print("Set ADMIN_USERNAME, ADMIN_PASSWORD, and ADMIN_EMAIL to create super admin user")
            print("(No super admin user was created)\n")
        
        conn.commit()
        print("Tables created successfully")
        
        cursor.close()
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Error creating tables: {e}")

def migrate_existing_database():
    """Migrate existing database to add new columns if they don't exist"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if role column exists in users table
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if "role" not in columns:
            print("Migrating users table: Adding 'role' column...")
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'health_officer'")
            conn.commit()
            print("✓ Added 'role' column")
        
        if "is_active" not in columns:
            print("Migrating users table: Adding 'is_active' column...")
            cursor.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
            conn.commit()
            print("✓ Added 'is_active' column")
        
        # Check if audit_log table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
        if not cursor.fetchone():
            print("Creating audit_log table...")
            cursor.execute("""
                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT NOT NULL,
                    table_name TEXT,
                    record_id INTEGER,
                    old_values TEXT,
                    new_values TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✓ Created audit_log table")
        
        # Check if backup_log table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='backup_log'")
        if not cursor.fetchone():
            print("Creating backup_log table...")
            cursor.execute("""
                CREATE TABLE backup_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_name TEXT NOT NULL,
                    backup_path TEXT NOT NULL,
                    backup_size INTEGER,
                    backup_type TEXT,
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✓ Created backup_log table")
        
        # Check if inventory table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='inventory'")
        if not cursor.fetchone():
            print("Creating inventory table...")
            cursor.execute("""
                CREATE TABLE inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_name TEXT NOT NULL,
                    category TEXT,
                    quantity INTEGER DEFAULT 0,
                    unit TEXT,
                    status TEXT DEFAULT 'available',
                    expiry_date DATE,
                    reorder_level INTEGER DEFAULT 5,
                    supplier TEXT,
                    notes TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✓ Created inventory table")
        
        # Check if documents table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='documents'")
        if not cursor.fetchone():
            print("Creating documents table...")
            cursor.execute("""
                CREATE TABLE documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document_name TEXT NOT NULL,
                    document_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    person_type TEXT,
                    person_id INTEGER,
                    description TEXT,
                    sensitivity_level TEXT DEFAULT 'confidential',
                    uploaded_by INTEGER NOT NULL,
                    uploaded_by_name TEXT,
                    is_verified INTEGER DEFAULT 0,
                    verified_by INTEGER,
                    verified_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✓ Created documents table")
        
        cursor.close()
        conn.close()
        print("Database migration complete!")
        
    except sqlite3.Error as e:
        print(f"Error during migration: {e}")

if __name__ == "__main__":
    print("Initializing SQLite database...")
    print(f"Database will be created at: {DATABASE}")
    create_tables()
    migrate_existing_database()
    print("Database initialization complete!")
    print(f"Database file location: {os.path.abspath(DATABASE)}")
