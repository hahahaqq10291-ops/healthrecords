"""
Encryption utilities for sensitive database fields
Uses Fernet symmetric encryption from cryptography library
"""

import os
from cryptography.fernet import Fernet

class DataEncryption:
    """Handle encryption and decryption of sensitive data"""
    
    def __init__(self, master_key=None):
        """
        Initialize encryption with a master key
        If no key provided, generates or loads from environment/file
        """
        if master_key:
            self.key = master_key.encode() if isinstance(master_key, str) else master_key
        else:
            self.key = self._get_or_create_key()
        
        try:
            self.cipher = Fernet(self.key)
        except Exception as e:
            raise ValueError(f"Invalid encryption key: {e}")
    
    def _get_or_create_key(self):
        """Get encryption key from environment or create/load from file"""
        key_env = os.environ.get('DATABASE_ENCRYPTION_KEY')
        if key_env:
            return key_env.encode()
        
        # Try to load from key file
        key_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', '.encryption_key')
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Restrict file permissions
            return key
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext string to ciphertext
        Returns base64-encoded ciphertext
        """
        if not plaintext:
            return None
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        try:
            ciphertext = self.cipher.encrypt(plaintext)
            return ciphertext.decode('utf-8')  # Return as string for database storage
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")
    
    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext back to plaintext
        Expects base64-encoded ciphertext string
        """
        if not ciphertext:
            return None
        
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        
        try:
            plaintext = self.cipher.decrypt(ciphertext)
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")


# Initialize global encryption instance
def get_encryption_handler(master_key=None):
    """Get or create encryption handler instance"""
    return DataEncryption(master_key)


# List of sensitive fields that should be encrypted
SENSITIVE_FIELDS = {
    'students': ['allergies', 'conditions', 'pastIllnesses', 'parentContact', 'emergencyContact', 'address', 'strand'],
    'teachers': ['allergies', 'conditions', 'pastIllnesses', 'contact', 'address'],
    'clinic_visits': ['diagnosis', 'assessment', 'physical_examination', 'medications_given', 'recommendations'],
    'documents': ['description'],
}


def should_encrypt_field(table, field):
    """Check if a field should be encrypted"""
    return table in SENSITIVE_FIELDS and field in SENSITIVE_FIELDS[table]
