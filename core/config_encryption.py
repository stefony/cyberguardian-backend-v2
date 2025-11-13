"""
CyberGuardian AI - Configuration Encryption
Secure encryption/decryption of sensitive configuration data
"""

import os
import json
import base64
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration paths
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
ENCRYPTED_CONFIG_FILE = CONFIG_DIR / "config.encrypted"
KEY_FILE = CONFIG_DIR / ".key"
BACKUP_KEY_FILE = CONFIG_DIR / ".key.backup"

# Ensure config directory exists
CONFIG_DIR.mkdir(exist_ok=True)


class ConfigEncryption:
    """
    Handles encryption and decryption of configuration files
    """
    
    def __init__(self):
        self.fernet = None
        self.key = None
        
    def generate_key(self, master_password: Optional[str] = None) -> bytes:
        """
        Generate encryption key
        
        Args:
            master_password: Optional master password for key derivation
            
        Returns:
            Encryption key
        """
        if master_password:
            # Derive key from password using PBKDF2
            salt = b"cyberguardian_salt_v1"  # In production, use random salt
            kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
)
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        else:
            # Generate random key
            key = Fernet.generate_key()
        
        logger.info("🔑 Encryption key generated")
        return key
    
    def save_key(self, key: bytes, backup: bool = True):
        """
        Save encryption key to file
        
        Args:
            key: Encryption key
            backup: Whether to create backup
        """
        try:
            # Save primary key
            with open(KEY_FILE, "wb") as f:
                f.write(key)
            
            # Restrict permissions (Unix-like systems)
            if os.name != "nt":
                os.chmod(KEY_FILE, 0o600)
            
            logger.info(f"✅ Key saved to {KEY_FILE}")
            
            # Save backup key
            if backup:
                with open(BACKUP_KEY_FILE, "wb") as f:
                    f.write(key)
                
                if os.name != "nt":
                    os.chmod(BACKUP_KEY_FILE, 0o600)
                
                logger.info(f"✅ Backup key saved to {BACKUP_KEY_FILE}")
            
        except Exception as e:
            logger.error(f"❌ Error saving key: {e}")
            raise
    
    def load_key(self, use_backup: bool = False) -> bytes:
        """
        Load encryption key from file
        
        Args:
            use_backup: Load from backup if primary fails
            
        Returns:
            Encryption key
        """
        try:
            key_path = BACKUP_KEY_FILE if use_backup else KEY_FILE
            
            if not key_path.exists():
                raise FileNotFoundError(f"Key file not found: {key_path}")
            
            with open(key_path, "rb") as f:
                key = f.read()
            
            logger.info(f"✅ Key loaded from {key_path}")
            return key
            
        except FileNotFoundError as e:
            if not use_backup and BACKUP_KEY_FILE.exists():
                logger.warning("⚠️ Primary key not found, trying backup...")
                return self.load_key(use_backup=True)
            raise
        except Exception as e:
            logger.error(f"❌ Error loading key: {e}")
            raise
    
    def initialize(self, master_password: Optional[str] = None, force_new: bool = False):
        """
        Initialize encryption system
        
        Args:
            master_password: Optional master password
            force_new: Force generation of new key
        """
        try:
            if force_new or not KEY_FILE.exists():
                # Generate new key
                self.key = self.generate_key(master_password)
                self.save_key(self.key, backup=True)
            else:
                # Load existing key
                self.key = self.load_key()
            
            # Initialize Fernet cipher
            self.fernet = Fernet(self.key)
            logger.info("✅ Encryption system initialized")
            
        except Exception as e:
            logger.error(f"❌ Error initializing encryption: {e}")
            raise
    
    def encrypt_config(self, config_data: Dict[str, Any]) -> bytes:
        """
        Encrypt configuration data
        
        Args:
            config_data: Configuration dictionary
            
        Returns:
            Encrypted data
        """
        if not self.fernet:
            raise RuntimeError("Encryption not initialized. Call initialize() first.")
        
        try:
            # Convert to JSON
            json_data = json.dumps(config_data, indent=2)
            
            # Encrypt
            encrypted_data = self.fernet.encrypt(json_data.encode())
            
            logger.info("✅ Configuration encrypted")
            return encrypted_data
            
        except Exception as e:
            logger.error(f"❌ Error encrypting config: {e}")
            raise
    
    def decrypt_config(self, encrypted_data: bytes) -> Dict[str, Any]:
        """
        Decrypt configuration data
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Configuration dictionary
        """
        if not self.fernet:
            raise RuntimeError("Encryption not initialized. Call initialize() first.")
        
        try:
            # Decrypt
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Parse JSON
            config_data = json.loads(decrypted_data.decode())
            
            logger.info("✅ Configuration decrypted")
            return config_data
            
        except Exception as e:
            logger.error(f"❌ Error decrypting config: {e}")
            raise
    
    def save_encrypted_config(self, config_data: Dict[str, Any]):
        """
        Encrypt and save configuration to file
        
        Args:
            config_data: Configuration dictionary
        """
        try:
            encrypted_data = self.encrypt_config(config_data)
            
            with open(ENCRYPTED_CONFIG_FILE, "wb") as f:
                f.write(encrypted_data)
            
            logger.info(f"✅ Encrypted config saved to {ENCRYPTED_CONFIG_FILE}")
            
        except Exception as e:
            logger.error(f"❌ Error saving encrypted config: {e}")
            raise
    
    def load_encrypted_config(self) -> Dict[str, Any]:
        """
        Load and decrypt configuration from file
        
        Returns:
            Configuration dictionary
        """
        try:
            if not ENCRYPTED_CONFIG_FILE.exists():
                raise FileNotFoundError(f"Encrypted config not found: {ENCRYPTED_CONFIG_FILE}")
            
            with open(ENCRYPTED_CONFIG_FILE, "rb") as f:
                encrypted_data = f.read()
            
            config_data = self.decrypt_config(encrypted_data)
            
            logger.info(f"✅ Encrypted config loaded from {ENCRYPTED_CONFIG_FILE}")
            return config_data
            
        except Exception as e:
            logger.error(f"❌ Error loading encrypted config: {e}")
            raise
    
    def rotate_key(self, new_master_password: Optional[str] = None):
        """
        Rotate encryption key (re-encrypt with new key)
        
        Args:
            new_master_password: New master password
        """
        try:
            # Load current config
            config_data = self.load_encrypted_config()
            
            # Backup old key
            old_key_backup = CONFIG_DIR / f".key.old.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            if KEY_FILE.exists():
                import shutil
                shutil.copy(KEY_FILE, old_key_backup)
                logger.info(f"✅ Old key backed up to {old_key_backup}")
            
            # Generate new key
            new_key = self.generate_key(new_master_password)
            self.key = new_key
            self.fernet = Fernet(new_key)
            
            # Save new key
            self.save_key(new_key, backup=True)
            
            # Re-encrypt config with new key
            self.save_encrypted_config(config_data)
            
            logger.info("✅ Key rotation completed successfully")
            
        except Exception as e:
            logger.error(f"❌ Error rotating key: {e}")
            raise
    
    def verify_integrity(self) -> bool:
        """
        Verify configuration integrity
        
        Returns:
            True if integrity check passes
        """
        try:
            # Try to decrypt config
            config = self.load_encrypted_config()
            
            # Basic validation
            if not isinstance(config, dict):
                logger.error("❌ Invalid config format")
                return False
            
            logger.info("✅ Configuration integrity verified")
            return True
            
        except Exception as e:
            logger.error(f"❌ Integrity check failed: {e}")
            return False


# Convenience functions
def encrypt_sensitive_data(data: Dict[str, Any], master_password: Optional[str] = None) -> bytes:
    """
    Quick encrypt function
    
    Args:
        data: Data to encrypt
        master_password: Optional master password
        
    Returns:
        Encrypted data
    """
    encryptor = ConfigEncryption()
    encryptor.initialize(master_password)
    return encryptor.encrypt_config(data)


def decrypt_sensitive_data(encrypted_data: bytes, master_password: Optional[str] = None) -> Dict[str, Any]:
    """
    Quick decrypt function
    
    Args:
        encrypted_data: Encrypted data
        master_password: Optional master password
        
    Returns:
        Decrypted data
    """
    encryptor = ConfigEncryption()
    encryptor.initialize(master_password)
    return encryptor.decrypt_config(encrypted_data)


# CLI for testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python config_encryption.py init [master_password]")
        print("  python config_encryption.py encrypt <config.json>")
        print("  python config_encryption.py decrypt")
        print("  python config_encryption.py rotate [new_master_password]")
        print("  python config_encryption.py verify")
        sys.exit(1)
    
    command = sys.argv[1]
    encryptor = ConfigEncryption()
    
    if command == "init":
        password = sys.argv[2] if len(sys.argv) > 2 else None
        encryptor.initialize(master_password=password, force_new=True)
        print("✅ Encryption initialized")
        
    elif command == "encrypt":
        if len(sys.argv) < 3:
            print("❌ Please provide config file path")
            sys.exit(1)
        
        config_file = sys.argv[2]
        with open(config_file, "r") as f:
            config_data = json.load(f)
        
        encryptor.initialize()
        encryptor.save_encrypted_config(config_data)
        print(f"✅ Config encrypted and saved")
        
    elif command == "decrypt":
        encryptor.initialize()
        config = encryptor.load_encrypted_config()
        print(json.dumps(config, indent=2))
        
    elif command == "rotate":
        password = sys.argv[2] if len(sys.argv) > 2 else None
        encryptor.initialize()
        encryptor.rotate_key(new_master_password=password)
        print("✅ Key rotated successfully")
        
    elif command == "verify":
        encryptor.initialize()
        if encryptor.verify_integrity():
            print("✅ Integrity check passed")
        else:
            print("❌ Integrity check failed")
            sys.exit(1)
    
    else:
        print(f"❌ Unknown command: {command}")
        sys.exit(1)