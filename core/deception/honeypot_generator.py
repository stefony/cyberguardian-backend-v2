"""
CyberGuardian AI - Honeypot Generator
Dynamic Deception System

Creates intelligent honeypots (fake assets) that:
- Attract attackers
- Detect intrusions
- Profile attacker behavior
- Waste attacker time
- Provide early warning

Security Knowledge Applied:
- Honeypot deployment strategies
- Canary tokens
- Deception technology
- Attacker psychology
- High-interaction honeypots
"""

import logging
import os
import platform
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import random
import string

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HoneypotType(Enum):
    """Types of honeypots"""
    FILE = "file"                    # Fake files
    FOLDER = "folder"                # Fake directories
    REGISTRY = "registry"            # Fake registry keys (Windows)
    CREDENTIAL = "credential"        # Fake credentials
    DATABASE = "database"            # Fake database files
    DOCUMENT = "document"            # Fake documents
    SHARE = "share"                  # Fake network shares
    SERVICE = "service"              # Fake network services


class HoneypotPriority(Enum):
    """Honeypot priority levels"""
    CRITICAL = 5    # High-value targets (passwords, databases)
    HIGH = 4        # Important files (configs, backups)
    MEDIUM = 3      # Normal files
    LOW = 2         # Low-interest files
    INFO = 1        # Information gathering


@dataclass
class Honeypot:
    """Honeypot metadata"""
    honeypot_id: str
    honeypot_type: HoneypotType
    name: str
    path: str
    priority: HoneypotPriority
    created_time: str
    last_accessed: Optional[str] = None
    access_count: int = 0
    description: str = ""
    monitored: bool = True


class HoneypotGenerator:
    """
    Dynamic honeypot generation and management system.
    Creates believable fake assets to deceive attackers.
    """
    
    # Honeypot templates
    FILE_TEMPLATES = {
        'passwords': [
            'passwords.txt', 'pass.txt', 'credentials.txt',
            'admin_passwords.xlsx', 'user_credentials.csv',
            'database_passwords.txt', 'ssh_keys.txt'
        ],
        'databases': [
            'database_backup.sql', 'users.db', 'customers.sqlite',
            'financial_data.mdb', 'production_backup.sql',
            'analytics.db', 'user_profiles.db'
        ],
        'configs': [
            'config.ini', 'settings.json', 'app.config',
            'database.yml', 'server_config.xml',
            '.env', 'secrets.json'
        ],
        'documents': [
            'Confidential_Report.docx', 'Financial_Statements_2024.xlsx',
            'Employee_Records.pdf', 'Strategic_Plan.pptx',
            'Salary_Info.xlsx', 'Client_List.csv'
        ],
        'keys': [
            'private_key.pem', 'id_rsa', 'api_key.txt',
            'ssl_certificate.key', 'jwt_secret.txt',
            'encryption_key.bin'
        ],
        'scripts': [
            'deploy.sh', 'backup_script.py', 'admin_tools.ps1',
            'database_migration.sql', 'setup.bat'
        ]
    }
    
    FOLDER_TEMPLATES = [
        'Admin', 'Backup', 'Confidential', 'Private',
        'Database_Backups', 'Financial_Reports', 'HR_Files',
        'Security_Logs', 'Credentials', 'Keys', 'Config'
    ]
    
    def __init__(self, honeypot_dir: str = None):
        """
        Initialize honeypot generator.
        
        Args:
            honeypot_dir: Directory for honeypots (default: ~/.cyberguardian/honeypots)
        """
        self.system = platform.system().lower()
        
        # Setup honeypot directory
        if honeypot_dir:
            self.honeypot_dir = Path(honeypot_dir)
        else:
            home = Path.home()
            self.honeypot_dir = home / '.cyberguardian' / 'honeypots'
        
        self.honeypot_dir.mkdir(parents=True, exist_ok=True)
        
        # Honeypot tracking
        self.honeypots: Dict[str, Honeypot] = {}
        self.metadata_file = self.honeypot_dir / 'honeypots.json'
        
        # Statistics
        self.stats = {
            'total_honeypots': 0,
            'active_honeypots': 0,
            'total_accesses': 0,
            'unique_attackers': 0,
            'triggered_alerts': 0
        }
        
        # Load existing honeypots
        self._load_metadata()
        
        logger.info(f"HoneypotGenerator initialized at {self.honeypot_dir}")
        logger.info(f"Active honeypots: {len(self.honeypots)}")
    
    def _load_metadata(self):
        """Load honeypot metadata from disk"""
        if not self.metadata_file.exists():
            return
        
        try:
            with open(self.metadata_file, 'r') as f:
                data = json.load(f)
            
            for hid, hp_dict in data.items():
                # Convert string enums back to enum objects
                hp_dict['honeypot_type'] = HoneypotType(hp_dict['honeypot_type'])
                hp_dict['priority'] = HoneypotPriority(hp_dict['priority'])
                self.honeypots[hid] = Honeypot(**hp_dict)
            
            logger.debug(f"Loaded {len(self.honeypots)} honeypots")
            
        except Exception as e:
            logger.error(f"Failed to load honeypots: {e}")
    
    def _save_metadata(self):
        """Save honeypot metadata to disk"""
        try:
            # Convert to serializable format
            data = {}
            for hid, hp in self.honeypots.items():
                hp_dict = asdict(hp)
                hp_dict['honeypot_type'] = hp.honeypot_type.value
                hp_dict['priority'] = hp.priority.value
                data[hid] = hp_dict
            
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug("Honeypot metadata saved")
            
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def _generate_honeypot_id(self) -> str:
        """Generate unique honeypot ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"HP_{timestamp}_{random_suffix}"
    
    def create_file_honeypot(self, category: str = None, 
                            custom_name: str = None,
                            custom_path: str = None,
                            priority: HoneypotPriority = HoneypotPriority.HIGH) -> Tuple[bool, str, Dict]:
        """
        Create a file honeypot.
        
        Args:
            category: Type of file ('passwords', 'databases', 'configs', etc.)
            custom_name: Custom filename (optional)
            custom_path: Custom path (optional)
            priority: Honeypot priority
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            # Select filename
            if custom_name:
                filename = custom_name
            elif category and category in self.FILE_TEMPLATES:
                filename = random.choice(self.FILE_TEMPLATES[category])
            else:
                # Random from all categories
                all_files = [f for files in self.FILE_TEMPLATES.values() for f in files]
                filename = random.choice(all_files)
            
            # Determine path
            if custom_path:
                file_path = Path(custom_path) / filename
            else:
                file_path = self.honeypot_dir / filename
            
            # Check if already exists
            if file_path.exists():
                return False, f"File already exists: {file_path}", {}
            
            # Create honeypot file with believable content
            content = self._generate_file_content(filename, category)
            
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w') as f:
                f.write(content)
            
            # Set file attributes to make it look legitimate
            self._set_file_attributes(file_path)
            
            # Create metadata
            honeypot_id = self._generate_honeypot_id()
            honeypot = Honeypot(
                honeypot_id=honeypot_id,
                honeypot_type=HoneypotType.FILE,
                name=filename,
                path=str(file_path),
                priority=priority,
                created_time=datetime.now().isoformat(),
                description=f"File honeypot: {category or 'general'}"
            )
            
            self.honeypots[honeypot_id] = honeypot
            self._save_metadata()
            
            self.stats['total_honeypots'] += 1
            self.stats['active_honeypots'] = len(self.honeypots)
            
            msg = f"File honeypot created: {filename}"
            logger.info(f"🍯 {msg}")
            
            details = {
                'honeypot_id': honeypot_id,
                'path': str(file_path),
                'priority': priority.name
            }
            
            return True, msg, details
            
        except Exception as e:
            error_msg = f"Failed to create file honeypot: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def _generate_file_content(self, filename: str, category: str = None) -> str:
        """
        Generate believable content for honeypot files.
        
        Args:
            filename: Name of the file
            category: Category of file
            
        Returns:
            File content as string
        """
        lower_name = filename.lower()
        
        # Passwords file
        if 'password' in lower_name or 'credential' in lower_name or category == 'passwords':
            return self._generate_fake_passwords()
        
        # Database backup
        elif '.sql' in lower_name or 'database' in lower_name or category == 'databases':
            return self._generate_fake_sql()
        
        # Config file
        elif 'config' in lower_name or '.ini' in lower_name or '.env' in lower_name:
            return self._generate_fake_config()
        
        # JSON
        elif '.json' in lower_name:
            return self._generate_fake_json()
        
        # CSV
        elif '.csv' in lower_name:
            return self._generate_fake_csv()
        
        # Keys
        elif 'key' in lower_name or '.pem' in lower_name or 'rsa' in lower_name:
            return self._generate_fake_key()
        
        # Script
        elif '.sh' in lower_name or '.py' in lower_name or '.ps1' in lower_name:
            return self._generate_fake_script(filename)
        
        # Default text content
        else:
            return self._generate_fake_document()
    
    def _generate_fake_passwords(self) -> str:
        """Generate fake password file content"""
        fake_users = ['admin', 'root', 'administrator', 'dbadmin', 'backup', 'service']
        fake_passwords = [
            'P@ssw0rd123!', 'Admin2024!', 'Welcome123',
            'Password1!', 'Admin@123', 'Backup2024'
        ]
        
        content = "# System Credentials - CONFIDENTIAL\n"
        content += "# Last updated: " + datetime.now().strftime("%Y-%m-%d") + "\n\n"
        
        for user in fake_users:
            password = random.choice(fake_passwords)
            content += f"{user}:{password}\n"
        
        content += "\n# Database Credentials\n"
        content += f"db_host=localhost\n"
        content += f"db_user=dbadmin\n"
        content += f"db_password={random.choice(fake_passwords)}\n"
        
        return content
    
    def _generate_fake_sql(self) -> str:
        """Generate fake SQL backup content"""
        return """-- Database Backup
-- Generated: """ + datetime.now().isoformat() + """
-- Database: production_db

CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(100),
    password_hash VARCHAR(255),
    created_at TIMESTAMP
);

INSERT INTO users VALUES (1, 'admin', 'admin@company.com', '$2b$12$...', NOW());
INSERT INTO users VALUES (2, 'john.doe', 'john@company.com', '$2b$12$...', NOW());

CREATE TABLE financial_data (
    transaction_id INT PRIMARY KEY,
    amount DECIMAL(10,2),
    account_number VARCHAR(20),
    timestamp TIMESTAMP
);

-- Backup completed successfully
"""
    
    def _generate_fake_config(self) -> str:
        """Generate fake config file"""
        return f"""[database]
host = localhost
port = 5432
username = admin
password = SecureP@ss123
database = production

[api]
api_key = sk_live_51HxT2JKl4mB8...
secret_key = whsec_f9a8d7b6c5...
endpoint = https://api.company.com

[security]
jwt_secret = your-secret-key-here
encryption_key = AES256-{os.urandom(16).hex()}
session_timeout = 3600

[admin]
admin_email = admin@company.com
admin_phone = +1-555-0123
"""
    
    def _generate_fake_json(self) -> str:
        """Generate fake JSON config"""
        config = {
            "database": {
                "host": "localhost",
                "port": 5432,
                "username": "admin",
                "password": "P@ssw0rd123"
            },
            "api_keys": {
                "stripe": "sk_live_51HxT2JKl4mB8...",
                "aws": "AKIAIOSFODNN7EXAMPLE",
                "sendgrid": "SG.abc123..."
            },
            "secrets": {
                "jwt_secret": "your-secret-key-here",
                "encryption_key": os.urandom(16).hex()
            }
        }
        return json.dumps(config, indent=2)
    
    def _generate_fake_csv(self) -> str:
        """Generate fake CSV with user data"""
        content = "user_id,username,email,role,salary\n"
        for i in range(1, 11):
            content += f"{i},user{i},user{i}@company.com,employee,{random.randint(50000, 150000)}\n"
        return content
    
    def _generate_fake_key(self) -> str:
        """Generate fake SSH/encryption key"""
        return """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2Z3qX5qY8N9vLm3pW8kH2dF6jK9sL4mN7oP8qR9sT0uV1wX2
Y3zAB4cD5eF6gH7iJ8kL9mN0oP1qR2sT3uV4wX5yY6zA7Bb8cC9dD0eE1fF2gG3h
... (fake key data) ...
-----END RSA PRIVATE KEY-----
"""
    
    def _generate_fake_script(self, filename: str) -> str:
        """Generate fake script content"""
        if filename.endswith('.sh'):
            return """#!/bin/bash
# Backup script
DB_USER="admin"
DB_PASS="P@ssw0rd123"
DB_NAME="production"

mysqldump -u $DB_USER -p$DB_PASS $DB_NAME > backup.sql
echo "Backup completed"
"""
        elif filename.endswith('.py'):
            return """#!/usr/bin/env python3
# Database migration script
import psycopg2

DB_CONFIG = {
    'host': 'localhost',
    'user': 'admin',
    'password': 'SecureP@ss123',
    'database': 'production'
}

def migrate():
    conn = psycopg2.connect(**DB_CONFIG)
    # Migration code here
    print("Migration completed")

if __name__ == '__main__':
    migrate()
"""
        else:
            return "# Admin script\n# Credentials: admin / P@ssw0rd123\n"
    
    def _generate_fake_document(self) -> str:
        """Generate fake document content"""
        return f"""CONFIDENTIAL DOCUMENT
Company: TechCorp Industries
Date: {datetime.now().strftime("%Y-%m-%d")}

This document contains sensitive information.

Access credentials:
- Admin portal: admin / P@ssw0rd123
- Database: dbadmin / SecureDB2024
- Backup server: backup / Backup@123

For internal use only.
"""
    
    def _set_file_attributes(self, file_path: Path):
        """Set file attributes to make honeypot look legitimate"""
        try:
            # Make file read-only to preserve it
            os.chmod(file_path, 0o444)
        except Exception as e:
            logger.debug(f"Could not set attributes: {e}")
    
    def create_folder_honeypot(self, folder_name: str = None,
                              custom_path: str = None) -> Tuple[bool, str, Dict]:
        """
        Create a folder honeypot.
        
        Args:
            folder_name: Name of folder (optional, random if not provided)
            custom_path: Custom path (optional)
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            # Select folder name
            if not folder_name:
                folder_name = random.choice(self.FOLDER_TEMPLATES)
            
            # Determine path
            if custom_path:
                folder_path = Path(custom_path) / folder_name
            else:
                folder_path = self.honeypot_dir / folder_name
            
            # Create folder
            folder_path.mkdir(parents=True, exist_ok=True)
            
            # Add some honeypot files inside
            for _ in range(random.randint(2, 5)):
                self.create_file_honeypot(
                    custom_path=str(folder_path),
                    priority=HoneypotPriority.MEDIUM
                )
            
            # Create metadata
            honeypot_id = self._generate_honeypot_id()
            honeypot = Honeypot(
                honeypot_id=honeypot_id,
                honeypot_type=HoneypotType.FOLDER,
                name=folder_name,
                path=str(folder_path),
                priority=HoneypotPriority.HIGH,
                created_time=datetime.now().isoformat(),
                description=f"Folder honeypot with fake files"
            )
            
            self.honeypots[honeypot_id] = honeypot
            self._save_metadata()
            
            self.stats['total_honeypots'] += 1
            self.stats['active_honeypots'] = len(self.honeypots)
            
            msg = f"Folder honeypot created: {folder_name}"
            logger.info(f"🍯 {msg}")
            
            details = {'honeypot_id': honeypot_id, 'path': str(folder_path)}
            return True, msg, details
            
        except Exception as e:
            error_msg = f"Failed to create folder honeypot: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def deploy_adaptive_honeypots(self, count: int = 10) -> Tuple[bool, str, Dict]:
        """
        Deploy multiple adaptive honeypots based on system environment.
        
        Args:
            count: Number of honeypots to deploy
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            logger.info(f"🍯 Deploying {count} adaptive honeypots...")
            
            deployed = 0
            failed = 0
            
            for _ in range(count):
                # Random category
                category = random.choice(list(self.FILE_TEMPLATES.keys()))
                
                success, msg, details = self.create_file_honeypot(
                    category=category,
                    priority=HoneypotPriority.HIGH
                )
                
                if success:
                    deployed += 1
                else:
                    failed += 1
            
            # Deploy some folder honeypots too
            for _ in range(count // 5):
                success, msg, details = self.create_folder_honeypot()
                if success:
                    deployed += 1
                else:
                    failed += 1
            
            result_msg = f"Deployed {deployed} honeypots ({failed} failed)"
            logger.info(f"✅ {result_msg}")
            
            return True, result_msg, {'deployed': deployed, 'failed': failed}
            
        except Exception as e:
            error_msg = f"Adaptive deployment failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def record_access(self, honeypot_id: str, attacker_info: Dict = None) -> bool:
        """
        Record an access to a honeypot (triggered alert).
        
        Args:
            honeypot_id: ID of accessed honeypot
            attacker_info: Information about attacker (optional)
            
        Returns:
            True if recorded successfully
        """
        try:
            if honeypot_id not in self.honeypots:
                return False
            
            honeypot = self.honeypots[honeypot_id]
            honeypot.last_accessed = datetime.now().isoformat()
            honeypot.access_count += 1
            
            self.stats['total_accesses'] += 1
            self.stats['triggered_alerts'] += 1
            
            self._save_metadata()
            
            logger.warning(f"🚨 HONEYPOT ACCESSED: {honeypot.name} "
                         f"(ID: {honeypot_id}, Priority: {honeypot.priority.name})")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to record access: {e}")
            return False
    
    def list_honeypots(self, honeypot_type: HoneypotType = None) -> List[Honeypot]:
        """List all honeypots with optional filtering"""
        honeypots = list(self.honeypots.values())
        
        if honeypot_type:
            honeypots = [hp for hp in honeypots if hp.honeypot_type == honeypot_type]
        
        return sorted(honeypots, key=lambda hp: hp.created_time, reverse=True)
    
    def get_statistics(self) -> Dict:
        """Get honeypot statistics"""
        self.stats['active_honeypots'] = len(self.honeypots)
        return self.stats.copy()
    
    def remove_honeypot(self, honeypot_id: str) -> Tuple[bool, str]:
        """Remove a honeypot"""
        try:
            if honeypot_id not in self.honeypots:
                return False, f"Honeypot not found: {honeypot_id}"
            
            honeypot = self.honeypots[honeypot_id]
            path = Path(honeypot.path)
            
            # Delete file/folder
            if path.exists():
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    import shutil
                    shutil.rmtree(path)
            
            # Remove from tracking
            del self.honeypots[honeypot_id]
            self._save_metadata()
            
            msg = f"Honeypot removed: {honeypot_id}"
            logger.info(msg)
            
            return True, msg
            
        except Exception as e:
            return False, f"Failed to remove honeypot: {str(e)}"


def create_honeypot_generator(honeypot_dir: str = None) -> HoneypotGenerator:
    """Factory function to create HoneypotGenerator instance"""
    return HoneypotGenerator(honeypot_dir=honeypot_dir)


# Testing
if __name__ == "__main__":
    print("🍯 CyberGuardian - Honeypot Generator Test\n")
    
    generator = create_honeypot_generator()
    
    print(f"📂 Honeypot directory: {generator.honeypot_dir}")
    
    print("\n🍯 Test 1: Create password file honeypot")
    success, message, details = generator.create_file_honeypot(
        category='passwords',
        priority=HoneypotPriority.CRITICAL
    )
    print(f"   {'✅' if success else '❌'} {message}")
    
    print("\n🍯 Test 2: Create database honeypot")
    success, message, details = generator.create_file_honeypot(
        category='databases',
        priority=HoneypotPriority.HIGH
    )
    print(f"   {'✅' if success else '❌'} {message}")
    
    print("\n🍯 Test 3: Create folder honeypot")
    success, message, details = generator.create_folder_honeypot()
    print(f"   {'✅' if success else '❌'} {message}")
    
    print("\n🍯 Test 4: Deploy adaptive honeypots")
    success, message, details = generator.deploy_adaptive_honeypots(count=5)
    print(f"   {'✅' if success else '❌'} {message}")
    print(f"   Deployed: {details.get('deployed', 0)}")
    
    print("\n📊 Statistics:")
    stats = generator.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n📋 Active honeypots:")
    honeypots = generator.list_honeypots()
    for hp in honeypots[:5]:
        print(f"   - {hp.name} ({hp.honeypot_type.value}) - Priority: {hp.priority.name}")
    
    print("\n✅ Honeypot Generator test complete!")
    print(f"\n⚠️  NOTE: Honeypots created at: {generator.honeypot_dir}")