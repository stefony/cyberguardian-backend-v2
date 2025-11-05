"""
CyberGuardian AI - Encryption Utility
Encrypt/Decrypt email passwords securely
"""

import os
from cryptography.fernet import Fernet
import base64
import logging

logger = logging.getLogger(__name__)

def get_encryption_key() -> bytes:
    """
    Get or generate encryption key from environment
    """
    key = os.getenv("EMAIL_ENCRYPTION_KEY")
    
    if not key:
        # Generate new key if not exists
        key = Fernet.generate_key().decode()
        logger.warning(f"⚠️ No EMAIL_ENCRYPTION_KEY found. Generated new key: {key}")
        logger.warning("⚠️ Please add this to your Railway environment variables!")
        return key.encode()
    
    return key.encode()


def encrypt_password(password: str) -> str:
    """
    Encrypt password using Fernet symmetric encryption
    
    Returns: Base64 encoded encrypted password
    """
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted = f.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        logger.error(f"Failed to encrypt password: {e}")
        raise


def decrypt_password(encrypted_password: str) -> str:
    """
    Decrypt password
    
    Returns: Plain text password
    """
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_password.encode())
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception as e:
        logger.error(f"Failed to decrypt password: {e}")
        raise


# Test function
if __name__ == "__main__":
    # Test encryption/decryption
    test_password = "test_password_123"
    
    print("🔐 Testing encryption...")
    encrypted = encrypt_password(test_password)
    print(f"Encrypted: {encrypted}")
    
    print("\n🔓 Testing decryption...")
    decrypted = decrypt_password(encrypted)
    print(f"Decrypted: {decrypted}")
    
    if decrypted == test_password:
        print("\n✅ Encryption/Decryption working correctly!")
    else:
        print("\n❌ Encryption/Decryption failed!")