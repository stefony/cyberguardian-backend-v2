"""
Registry Cleaner - Windows Registry Malware Persistence Detection & Removal
Scans common autorun registry keys and removes malicious entries
"""

import winreg
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import os
import platform

# Common autorun registry keys that malware uses for persistence
AUTORUN_KEYS = [
    # HKEY_LOCAL_MACHINE (System-wide)
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    
    # HKEY_CURRENT_USER (User-specific)
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    
    # Startup folders (via registry)
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
]

# Suspicious indicators in registry values
SUSPICIOUS_PATTERNS = [
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "\\AppData\\Local\\Temp\\",
    "\\Users\\Public\\",
    "%TEMP%",
    "%TMP%",
    "http://",
    "https://",
    ".tmp",
    ".vbs",
    ".js",
    ".bat",
    ".ps1",
]

# Known legitimate programs (whitelist)
WHITELIST = [
    "SecurityHealthSystray.exe",  # Windows Defender
    "OneDrive.exe",
    "Teams.exe",
    "Spotify.exe",
    "Discord.exe",
    "Skype.exe",
    "chrome.exe",
    "firefox.exe",
    "explorer.exe",
    # Add more legitimate programs as needed
]


class RegistryCleaner:
    """Windows Registry cleaner for malware persistence removal"""
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.backup_dir = "registry_backups"
        self._ensure_backup_dir()
    
    def _ensure_backup_dir(self):
        """Create backup directory if it doesn't exist"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def scan_registry(self) -> List[Dict]:
        """
        Scan all autorun registry keys for suspicious entries
        
        Returns:
            List of suspicious registry entries with details
        """
        if not self.is_windows:
            return []
        
        suspicious_entries = []
        
        for hive, key_path in AUTORUN_KEYS:
            try:
                entries = self._scan_key(hive, key_path)
                suspicious_entries.extend(entries)
            except Exception as e:
                print(f"Error scanning {key_path}: {str(e)}")
                continue
        
        return suspicious_entries
    
    def _scan_key(self, hive: int, key_path: str) -> List[Dict]:
        """
        Scan a specific registry key for suspicious entries
        
        Args:
            hive: Registry hive (HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.)
            key_path: Path to the registry key
            
        Returns:
            List of suspicious entries in this key
        """
        suspicious_entries = []
        hive_name = self._get_hive_name(hive)
        
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        except FileNotFoundError:
            # Key doesn't exist, skip
            return []
        except PermissionError:
            print(f"Permission denied: {hive_name}\\{key_path}")
            return []
        
        try:
            index = 0
            while True:
                try:
                    # Enumerate all values in the key
                    value_name, value_data, value_type = winreg.EnumValue(key, index)
                    
                    # Analyze the value
                    if self._is_suspicious(value_name, value_data):
                        entry = {
                            "id": hashlib.md5(f"{hive_name}\\{key_path}\\{value_name}".encode()).hexdigest(),
                            "hive": hive_name,
                            "key_path": key_path,
                            "value_name": value_name,
                            "value_data": str(value_data),
                            "value_type": self._get_value_type_name(value_type),
                            "risk_score": self._calculate_risk_score(value_data),
                            "indicators": self._get_indicators(value_data),
                            "scanned_at": datetime.utcnow().isoformat(),
                        }
                        suspicious_entries.append(entry)
                    
                    index += 1
                except OSError:
                    # No more values
                    break
        finally:
            winreg.CloseKey(key)
        
        return suspicious_entries
    
    def _is_suspicious(self, value_name: str, value_data: str) -> bool:
        """
        Check if a registry value is suspicious
        
        Args:
            value_name: Name of the registry value
            value_data: Data of the registry value
            
        Returns:
            True if suspicious, False otherwise
        """
        value_data_str = str(value_data).lower()
        
        # Check whitelist first
        for safe_program in WHITELIST:
            if safe_program.lower() in value_data_str:
                return False
        
        # Check for suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in value_data_str:
                return True
        
        # Check if file exists (if it's a file path)
        if "\\" in value_data_str or "/" in value_data_str:
            # Extract potential file path
            potential_path = value_data_str.split()[0].strip('"')
            if not os.path.exists(potential_path):
                # File doesn't exist - suspicious!
                return True
        
        return False
    
    def _calculate_risk_score(self, value_data: str) -> int:
        """
        Calculate risk score (0-100) based on suspicious indicators
        
        Args:
            value_data: Registry value data
            
        Returns:
            Risk score from 0-100
        """
        score = 0
        value_data_lower = str(value_data).lower()
        
        # High-risk patterns
        high_risk = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "regsvr32.exe"]
        for pattern in high_risk:
            if pattern in value_data_lower:
                score += 30
        
        # Medium-risk patterns
        medium_risk = ["\\temp\\", "\\appdata\\local\\temp\\", "%temp%", ".tmp", ".vbs", ".bat"]
        for pattern in medium_risk:
            if pattern in value_data_lower:
                score += 20
        
        # Low-risk patterns
        low_risk = ["http://", "https://", "download"]
        for pattern in low_risk:
            if pattern in value_data_lower:
                score += 10
        
        # File doesn't exist
        if "\\" in value_data_lower:
            potential_path = value_data_lower.split()[0].strip('"')
            if not os.path.exists(potential_path):
                score += 25
        
        return min(score, 100)
    
    def _get_indicators(self, value_data: str) -> List[str]:
        """
        Get list of suspicious indicators found in value data
        
        Args:
            value_data: Registry value data
            
        Returns:
            List of indicator descriptions
        """
        indicators = []
        value_data_lower = str(value_data).lower()
        
        if any(p in value_data_lower for p in ["cmd.exe", "powershell.exe", "wscript.exe"]):
            indicators.append("Uses scripting/command line tool")
        
        if any(p in value_data_lower for p in ["\\temp\\", "%temp%", ".tmp"]):
            indicators.append("References temporary directory")
        
        if "http://" in value_data_lower or "https://" in value_data_lower:
            indicators.append("Contains URL")
        
        if "\\" in value_data_lower:
            potential_path = value_data_lower.split()[0].strip('"')
            if not os.path.exists(potential_path):
                indicators.append("File does not exist")
        
        if any(ext in value_data_lower for ext in [".vbs", ".js", ".bat", ".ps1"]):
            indicators.append("Script file extension")
        
        return indicators
    
    def backup_key(self, hive: int, key_path: str, value_name: str) -> str:
        """
        Backup a registry key before modification
        
        Args:
            hive: Registry hive
            key_path: Path to the registry key
            value_name: Name of the value to backup
            
        Returns:
            Path to backup file
        """
        if not self.is_windows:
            return ""
        
        hive_name = self._get_hive_name(hive)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_id = hashlib.md5(f"{hive_name}\\{key_path}\\{value_name}".encode()).hexdigest()[:8]
        backup_file = os.path.join(self.backup_dir, f"backup_{timestamp}_{backup_id}.json")
        
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            value_data, value_type = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            
            backup_data = {
                "hive": hive_name,
                "key_path": key_path,
                "value_name": value_name,
                "value_data": str(value_data),
                "value_type": self._get_value_type_name(value_type),
                "backed_up_at": datetime.utcnow().isoformat(),
            }
            
            with open(backup_file, "w") as f:
                json.dump(backup_data, f, indent=2)
            
            return backup_file
        
        except Exception as e:
            print(f"Error backing up registry key: {str(e)}")
            return ""
    
    def remove_entry(self, hive_name: str, key_path: str, value_name: str) -> Tuple[bool, str]:
        """
        Remove a registry entry (with automatic backup)
        
        Args:
            hive_name: Name of the hive (e.g., "HKEY_LOCAL_MACHINE")
            key_path: Path to the registry key
            value_name: Name of the value to remove
            
        Returns:
            Tuple of (success, message/backup_file)
        """
        if not self.is_windows:
            return False, "Not a Windows system"
        
        hive = self._get_hive_from_name(hive_name)
        
        # Backup first
        backup_file = self.backup_key(hive, key_path, value_name)
        if not backup_file:
            return False, "Failed to create backup"
        
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            return True, backup_file
        
        except PermissionError:
            return False, "Permission denied - run as administrator"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def restore_entry(self, backup_file: str) -> Tuple[bool, str]:
        """
        Restore a registry entry from backup
        
        Args:
            backup_file: Path to backup file
            
        Returns:
            Tuple of (success, message)
        """
        if not self.is_windows:
            return False, "Not a Windows system"
        
        if not os.path.exists(backup_file):
            return False, "Backup file not found"
        
        try:
            with open(backup_file, "r") as f:
                backup_data = json.load(f)
            
            hive = self._get_hive_from_name(backup_data["hive"])
            key_path = backup_data["key_path"]
            value_name = backup_data["value_name"]
            value_data = backup_data["value_data"]
            
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
            winreg.CloseKey(key)
            
            return True, "Registry entry restored successfully"
        
        except Exception as e:
            return False, f"Error restoring: {str(e)}"
    
    def _get_hive_name(self, hive: int) -> str:
        """Convert hive constant to name"""
        hive_names = {
            winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
            winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
            winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
            winreg.HKEY_USERS: "HKEY_USERS",
            winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG",
        }
        return hive_names.get(hive, "UNKNOWN")
    
    def _get_hive_from_name(self, hive_name: str) -> int:
        """Convert hive name to constant"""
        hive_map = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_USERS": winreg.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        }
        return hive_map.get(hive_name, winreg.HKEY_LOCAL_MACHINE)
    
    def _get_value_type_name(self, value_type: int) -> str:
        """Convert registry value type to name"""
        type_names = {
            winreg.REG_SZ: "REG_SZ",
            winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
            winreg.REG_BINARY: "REG_BINARY",
            winreg.REG_DWORD: "REG_DWORD",
            winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
        }
        return type_names.get(value_type, "UNKNOWN")
    
    def get_statistics(self, entries: List[Dict]) -> Dict:
        """
        Get statistics from scan results
        
        Args:
            entries: List of suspicious entries
            
        Returns:
            Statistics dictionary
        """
        if not entries:
            return {
                "total_suspicious": 0,
                "critical_risk": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "by_hive": {},
            }
        
        stats = {
            "total_suspicious": len(entries),
            "critical_risk": len([e for e in entries if e["risk_score"] >= 80]),
            "high_risk": len([e for e in entries if 60 <= e["risk_score"] < 80]),
            "medium_risk": len([e for e in entries if 40 <= e["risk_score"] < 60]),
            "low_risk": len([e for e in entries if e["risk_score"] < 40]),
            "by_hive": {},
        }
        
        # Count by hive
        for entry in entries:
            hive = entry["hive"]
            stats["by_hive"][hive] = stats["by_hive"].get(hive, 0) + 1
        
        return stats


# Standalone functions for database integration
def scan_registry_entries() -> List[Dict]:
    """Scan registry for suspicious entries"""
    cleaner = RegistryCleaner()
    return cleaner.scan_registry()


def remove_registry_entry(hive: str, key_path: str, value_name: str) -> Tuple[bool, str]:
    """Remove a registry entry with backup"""
    cleaner = RegistryCleaner()
    return cleaner.remove_entry(hive, key_path, value_name)


def restore_registry_entry(backup_file: str) -> Tuple[bool, str]:
    """Restore a registry entry from backup"""
    cleaner = RegistryCleaner()
    return cleaner.restore_entry(backup_file)


def get_registry_statistics(entries: List[Dict]) -> Dict:
    """Get statistics from registry scan"""
    cleaner = RegistryCleaner()
    return cleaner.get_statistics(entries)