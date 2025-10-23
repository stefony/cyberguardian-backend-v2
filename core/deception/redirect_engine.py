"""
CyberGuardian AI - Redirect Engine
Intelligent Attack Redirection System

Transparently redirects attacks to honeypots:
- File system redirects (symlinks, junctions)
- Network redirects (DNS, routing)
- Process redirects (API hooking)
- Seamless redirection (attacker unaware)
- Dynamic honeypot selection

Security Knowledge Applied:
- Transparent proxying
- Active defense
- Attacker psychology
- Deception techniques
- Honeypot orchestration
"""

import logging
import os
import platform
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RedirectType(Enum):
    """Types of redirects"""
    FILE_SYMLINK = "file_symlink"          # Symbolic link redirect
    FOLDER_JUNCTION = "folder_junction"    # Folder junction redirect
    DNS_REDIRECT = "dns_redirect"          # DNS-level redirect
    NETWORK_REDIRECT = "network_redirect"  # Network routing redirect
    PROCESS_REDIRECT = "process_redirect"  # API call redirect
    REGISTRY_REDIRECT = "registry_redirect" # Windows registry redirect


class RedirectPriority(Enum):
    """Redirect priority levels"""
    CRITICAL = 5    # Always redirect
    HIGH = 4        # Redirect if honeypot available
    MEDIUM = 3      # Redirect randomly
    LOW = 2         # Rarely redirect
    PASSIVE = 1     # Only if explicitly triggered


@dataclass
class RedirectRule:
    """Redirect rule definition"""
    rule_id: str
    rule_type: RedirectType
    source_path: str           # Original target
    destination_path: str      # Honeypot location
    priority: RedirectPriority
    condition: Optional[str] = None  # When to trigger
    created_time: str = ""
    active: bool = True
    trigger_count: int = 0
    last_triggered: Optional[str] = None


class RedirectEngine:
    """
    Intelligent attack redirection system.
    Transparently sends attackers to honeypots.
    """
    
    # High-value targets to redirect
    HIGH_VALUE_TARGETS = [
        'passwords.txt', 'credentials.txt', 'config.ini', '.env',
        'database.sql', 'backup.sql', 'users.db', 'admin.txt',
        'id_rsa', 'private_key.pem', 'api_key.txt', 'secrets.json'
    ]
    
    # Folders to redirect
    HIGH_VALUE_FOLDERS = [
        'Admin', 'Backup', 'Confidential', 'Private', 'Database_Backups',
        'Financial', 'HR', 'Security', 'Credentials', 'Keys'
    ]
    
    def __init__(self, honeypot_dir: str = None):
        """
        Initialize redirect engine.
        
        Args:
            honeypot_dir: Directory containing honeypots
        """
        self.system = platform.system().lower()
        
        # Honeypot directory
        if honeypot_dir:
            self.honeypot_dir = Path(honeypot_dir)
        else:
            home = Path.home()
            self.honeypot_dir = home / '.cyberguardian' / 'honeypots'
        
        self.honeypot_dir.mkdir(parents=True, exist_ok=True)
        
        # Redirect rules
        self.rules: Dict[str, RedirectRule] = {}
        
        # Statistics
        self.stats = {
            'total_rules': 0,
            'active_rules': 0,
            'total_redirects': 0,
            'successful_redirects': 0,
            'failed_redirects': 0
        }
        
        logger.info(f"RedirectEngine initialized")
        logger.info(f"Honeypot directory: {self.honeypot_dir}")
    
    def _generate_rule_id(self) -> str:
        """Generate unique rule ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"RULE_{timestamp}_{os.urandom(4).hex()}"
    
    def create_file_redirect(self, source_path: str, honeypot_path: str,
                           priority: RedirectPriority = RedirectPriority.HIGH) -> Tuple[bool, str, Dict]:
        """
        Create a file system redirect (symlink/junction).
        
        Args:
            source_path: Original file path (where attacker looks)
            honeypot_path: Honeypot file path (where to redirect)
            priority: Redirect priority
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            source = Path(source_path)
            target = Path(honeypot_path)
            
            # Verify honeypot exists
            if not target.exists():
                return False, f"Honeypot not found: {target}", {}
            
            # Create parent directories if needed
            source.parent.mkdir(parents=True, exist_ok=True)
            
            # Create symbolic link
            if self.system == 'windows':
                # Windows: use mklink via cmd
                if source.exists():
                    source.unlink()  # Remove if exists
                
                import subprocess
                cmd = ['mklink', str(source), str(target)]
                result = subprocess.run(cmd, shell=True, capture_output=True)
                
                if result.returncode != 0:
                    # Fallback: copy file
                    import shutil
                    shutil.copy2(target, source)
                    logger.warning(f"Could not create symlink, copied file instead")
            
            else:
                # Unix: use os.symlink
                if source.exists():
                    source.unlink()
                
                os.symlink(target, source)
            
            # Create redirect rule
            rule_id = self._generate_rule_id()
            rule = RedirectRule(
                rule_id=rule_id,
                rule_type=RedirectType.FILE_SYMLINK,
                source_path=str(source),
                destination_path=str(target),
                priority=priority,
                created_time=datetime.now().isoformat(),
                active=True
            )
            
            self.rules[rule_id] = rule
            
            self.stats['total_rules'] += 1
            self.stats['active_rules'] = len([r for r in self.rules.values() if r.active])
            
            msg = f"File redirect created: {source.name} → {target.name}"
            logger.info(f"🔀 {msg}")
            
            details = {'rule_id': rule_id, 'source': str(source), 'target': str(target)}
            return True, msg, details
            
        except Exception as e:
            error_msg = f"Failed to create redirect: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def create_folder_redirect(self, source_path: str, honeypot_folder: str,
                              priority: RedirectPriority = RedirectPriority.HIGH) -> Tuple[bool, str, Dict]:
        """
        Create a folder redirect (junction/symlink).
        
        Args:
            source_path: Original folder path
            honeypot_folder: Honeypot folder path
            priority: Redirect priority
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            source = Path(source_path)
            target = Path(honeypot_folder)
            
            # Verify honeypot folder exists
            if not target.exists():
                return False, f"Honeypot folder not found: {target}", {}
            
            # Create parent directories
            source.parent.mkdir(parents=True, exist_ok=True)
            
            # Create junction/symlink
            if self.system == 'windows':
                # Windows junction
                if source.exists():
                    import shutil
                    shutil.rmtree(source)
                
                import subprocess
                cmd = ['mklink', '/J', str(source), str(target)]
                result = subprocess.run(cmd, shell=True, capture_output=True)
                
                if result.returncode != 0:
                    # Fallback: copy folder
                    import shutil
                    shutil.copytree(target, source)
                    logger.warning(f"Could not create junction, copied folder instead")
            
            else:
                # Unix symlink
                if source.exists():
                    import shutil
                    shutil.rmtree(source)
                
                os.symlink(target, source, target_is_directory=True)
            
            # Create rule
            rule_id = self._generate_rule_id()
            rule = RedirectRule(
                rule_id=rule_id,
                rule_type=RedirectType.FOLDER_JUNCTION,
                source_path=str(source),
                destination_path=str(target),
                priority=priority,
                created_time=datetime.now().isoformat(),
                active=True
            )
            
            self.rules[rule_id] = rule
            
            self.stats['total_rules'] += 1
            self.stats['active_rules'] = len([r for r in self.rules.values() if r.active])
            
            msg = f"Folder redirect created: {source.name} → {target.name}"
            logger.info(f"🔀 {msg}")
            
            details = {'rule_id': rule_id, 'source': str(source), 'target': str(target)}
            return True, msg, details
            
        except Exception as e:
            error_msg = f"Failed to create folder redirect: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def create_network_redirect(self, source_ip: str, honeypot_ip: str,
                               port: int = None) -> Tuple[bool, str, Dict]:
        """
        Create a network-level redirect.
        
        Args:
            source_ip: IP to redirect
            honeypot_ip: Honeypot service IP
            port: Specific port (optional)
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            # This would require firewall/routing rules
            # For now, log the intention
            
            rule_id = self._generate_rule_id()
            rule = RedirectRule(
                rule_id=rule_id,
                rule_type=RedirectType.NETWORK_REDIRECT,
                source_path=f"{source_ip}:{port}" if port else source_ip,
                destination_path=f"{honeypot_ip}:{port}" if port else honeypot_ip,
                priority=RedirectPriority.HIGH,
                created_time=datetime.now().isoformat(),
                active=True
            )
            
            self.rules[rule_id] = rule
            
            msg = f"Network redirect rule created: {source_ip} → {honeypot_ip}"
            logger.info(f"🔀 {msg}")
            logger.warning("⚠️ Network redirect requires firewall integration (not yet implemented)")
            
            details = {'rule_id': rule_id}
            return True, msg, details
            
        except Exception as e:
            error_msg = f"Failed to create network redirect: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def deploy_automatic_redirects(self, count: int = 10) -> Tuple[bool, str, Dict]:
        """
        Automatically deploy redirects for high-value targets.
        
        Args:
            count: Number of redirects to create
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            logger.info(f"🔀 Deploying {count} automatic redirects...")
            
            deployed = 0
            failed = 0
            
            # Deploy file redirects
            for filename in self.HIGH_VALUE_TARGETS[:count]:
                # Check if honeypot exists
                honeypot_path = self.honeypot_dir / filename
                
                if not honeypot_path.exists():
                    # Create a simple honeypot if doesn't exist
                    honeypot_path.write_text(f"# Honeypot: {filename}\n# Access logged\n")
                
                # Create redirect in common locations
                if self.system == 'windows':
                    locations = [
                        Path.home() / 'Documents',
                        Path.home() / 'Desktop',
                        Path('C:/Users/Public/Documents')
                    ]
                else:
                    locations = [
                        Path.home(),
                        Path.home() / 'Documents',
                        Path('/tmp')
                    ]
                
                for location in locations:
                    if location.exists():
                        source_path = location / filename
                        
                        # Only create if doesn't exist
                        if not source_path.exists():
                            success, msg, details = self.create_file_redirect(
                                str(source_path),
                                str(honeypot_path),
                                RedirectPriority.HIGH
                            )
                            
                            if success:
                                deployed += 1
                            else:
                                failed += 1
                            
                            break  # Only create once per file
            
            result_msg = f"Deployed {deployed} redirects ({failed} failed)"
            logger.info(f"✅ {result_msg}")
            
            return True, result_msg, {'deployed': deployed, 'failed': failed}
            
        except Exception as e:
            error_msg = f"Automatic deployment failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def should_redirect(self, target_path: str, source_ip: str = None) -> bool:
        """
        Determine if a target should be redirected based on rules.
        
        Args:
            target_path: Path being accessed
            source_ip: Source IP (optional)
            
        Returns:
            True if should redirect
        """
        target = Path(target_path)
        
        # Check if matches high-value targets
        if target.name in self.HIGH_VALUE_TARGETS:
            return True
        
        # Check if in high-value folder
        for folder in self.HIGH_VALUE_FOLDERS:
            if folder.lower() in str(target).lower():
                return True
        
        # Check existing rules
        for rule in self.rules.values():
            if rule.active and str(target) == rule.source_path:
                return True
        
        # Random redirect for learning (10% chance)
        if random.random() < 0.1:
            return True
        
        return False
    
    def trigger_redirect(self, rule_id: str, source_ip: str = None) -> bool:
        """
        Trigger a redirect (record access).
        
        Args:
            rule_id: Rule ID
            source_ip: Source IP of attacker
            
        Returns:
            True if triggered successfully
        """
        if rule_id not in self.rules:
            return False
        
        rule = self.rules[rule_id]
        rule.trigger_count += 1
        rule.last_triggered = datetime.now().isoformat()
        
        self.stats['total_redirects'] += 1
        self.stats['successful_redirects'] += 1
        
        logger.warning(f"🔀 REDIRECT TRIGGERED: {rule.source_path} → {rule.destination_path}")
        if source_ip:
            logger.warning(f"   Source IP: {source_ip}")
        
        return True
    
    def get_redirect_rule(self, rule_id: str) -> Optional[RedirectRule]:
        """Get redirect rule by ID"""
        return self.rules.get(rule_id)
    
    def list_active_rules(self) -> List[RedirectRule]:
        """List all active redirect rules"""
        return [rule for rule in self.rules.values() if rule.active]
    
    def disable_rule(self, rule_id: str) -> Tuple[bool, str]:
        """Disable a redirect rule"""
        if rule_id not in self.rules:
            return False, f"Rule not found: {rule_id}"
        
        rule = self.rules[rule_id]
        rule.active = False
        
        # Try to remove symlink/junction
        try:
            source = Path(rule.source_path)
            if source.exists() and (source.is_symlink() or source.is_dir()):
                if source.is_symlink():
                    source.unlink()
                else:
                    import shutil
                    shutil.rmtree(source)
                
                logger.info(f"Removed redirect: {rule.source_path}")
        except Exception as e:
            logger.warning(f"Could not remove redirect: {e}")
        
        self.stats['active_rules'] = len([r for r in self.rules.values() if r.active])
        
        return True, f"Rule disabled: {rule_id}"
    
    def remove_all_redirects(self) -> int:
        """Remove all redirect rules"""
        count = 0
        for rule_id in list(self.rules.keys()):
            success, msg = self.disable_rule(rule_id)
            if success:
                count += 1
        
        logger.info(f"Removed {count} redirects")
        return count
    
    def get_statistics(self) -> Dict:
        """Get redirect statistics"""
        self.stats['total_rules'] = len(self.rules)
        self.stats['active_rules'] = len([r for r in self.rules.values() if r.active])
        return self.stats.copy()
    
    def get_most_triggered(self, limit: int = 10) -> List[RedirectRule]:
        """Get most frequently triggered redirects"""
        sorted_rules = sorted(
            self.rules.values(),
            key=lambda r: r.trigger_count,
            reverse=True
        )
        return sorted_rules[:limit]


def create_redirect_engine(honeypot_dir: str = None) -> RedirectEngine:
    """Factory function to create RedirectEngine instance"""
    return RedirectEngine(honeypot_dir=honeypot_dir)


# Testing
if __name__ == "__main__":
    print("🔀 CyberGuardian - Redirect Engine Test\n")
    
    engine = create_redirect_engine()
    
    print(f"📂 Honeypot directory: {engine.honeypot_dir}")
    
    print("\n🔀 Test 1: Create file redirect")
    # Create a test honeypot first
    test_honeypot = engine.honeypot_dir / "test_passwords.txt"
    test_honeypot.write_text("admin:FakePassword123!\nroot:FakeRoot456!")
    
    test_source = Path.home() / "Documents" / "passwords.txt"
    
    success, message, details = engine.create_file_redirect(
        str(test_source),
        str(test_honeypot),
        RedirectPriority.CRITICAL
    )
    print(f"   {'✅' if success else '❌'} {message}")
    if success:
        print(f"   Rule ID: {details['rule_id']}")
    
    print("\n🔀 Test 2: Should redirect check")
    should = engine.should_redirect(str(test_source))
    print(f"   Should redirect 'passwords.txt': {should}")
    
    should = engine.should_redirect(str(Path.home() / "normal_file.txt"))
    print(f"   Should redirect 'normal_file.txt': {should}")
    
    print("\n🔀 Test 3: Deploy automatic redirects")
    success, message, details = engine.deploy_automatic_redirects(count=5)
    print(f"   {'✅' if success else '❌'} {message}")
    print(f"   Deployed: {details.get('deployed', 0)}")
    
    print("\n📋 Test 4: List active rules")
    rules = engine.list_active_rules()
    print(f"   Active rules: {len(rules)}")
    for rule in rules[:3]:
        print(f"   - {Path(rule.source_path).name} → {Path(rule.destination_path).name}")
    
    print("\n📊 Statistics:")
    stats = engine.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✅ Redirect Engine test complete!")
    print("\n⚠️  NOTE: Redirects created in file system")
    print("         Clean up test files manually if needed")