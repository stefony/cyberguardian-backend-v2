"""
Service Manager - Windows Services Malware Detection & Removal
Scans Windows services for suspicious entries and provides removal with backup
"""

import json
import hashlib
import os
import platform
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Platform-specific imports
if platform.system() == "Windows":
    import win32service
    import win32serviceutil
    import pywintypes
else:
    # Mock classes for non-Windows systems
    class MockWin32Service:
        SC_MANAGER_ALL_ACCESS = 0
        SERVICE_ALL_ACCESS = 0
        SERVICE_AUTO_START = 2
        SERVICE_BOOT_START = 0
        SERVICE_DEMAND_START = 3
        SERVICE_DISABLED = 4
        SERVICE_SYSTEM_START = 1
        SERVICE_RUNNING = 4
        SERVICE_STOPPED = 1
        
        @staticmethod
        def OpenSCManager(*args, **kwargs):
            raise OSError("Not a Windows system")
        
        @staticmethod
        def EnumServicesStatus(*args, **kwargs):
            return []
        
        @staticmethod
        def OpenService(*args, **kwargs):
            raise OSError("Not a Windows system")
        
        @staticmethod
        def QueryServiceConfig(*args, **kwargs):
            raise OSError("Not a Windows system")
        
        @staticmethod
        def ControlService(*args, **kwargs):
            raise OSError("Not a Windows system")
        
        @staticmethod
        def DeleteService(*args, **kwargs):
            raise OSError("Not a Windows system")
        
        @staticmethod
        def CloseServiceHandle(*args, **kwargs):
            pass
    
    win32service = MockWin32Service()
    win32serviceutil = MockWin32Service()

# Suspicious service indicators
SUSPICIOUS_PATTERNS = [
    # Executable locations
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "%temp%",
    "%tmp%",
    
    # Suspicious names
    "miner",
    "crypto",
    "botnet",
    "keylog",
    "backdoor",
    "trojan",
    "rootkit",
    
    # Script extensions
    ".bat",
    ".vbs",
    ".ps1",
    ".js",
    
    # Suspicious behaviors
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
]

# Known legitimate services (whitelist)
WHITELIST = [
    "wuauserv",  # Windows Update
    "wscsvc",    # Security Center
    "windefend", # Windows Defender
    "mpssvc",    # Windows Firewall
    "bits",      # Background Intelligent Transfer
    "eventlog",  # Event Log
    "lanmanserver", # Server
    "lanmanworkstation", # Workstation
    "dnscache",  # DNS Client
    "dhcp",      # DHCP Client
    "w32time",   # Windows Time
    "schedule",  # Task Scheduler
    "spooler",   # Print Spooler
    # Add more Windows core services
]

# Suspicious service characteristics
SUSPICIOUS_STARTUP_TYPES = [
    "Automatic",  # Auto-start services
    "Boot",       # Boot-start drivers
]


class ServiceManager:
    """Windows Service manager for malware detection and removal"""
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.backup_dir = "service_backups"
        self._ensure_backup_dir()
    
    def _ensure_backup_dir(self):
        """Create backup directory if it doesn't exist"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def scan_services(self) -> List[Dict]:
        """
        Scan all Windows services for suspicious entries
        
        Returns:
            List of suspicious services with details
        """
        if not self.is_windows:
            return []
        
        suspicious_services = []
        
        try:
            # Open Service Control Manager
            scm_handle = win32service.OpenSCManager(
                None,
                None,
                win32service.SC_MANAGER_ALL_ACCESS
            )
            
            try:
                # Enumerate all services
                service_type = win32service.SERVICE_WIN32
                service_state = win32service.SERVICE_STATE_ALL
                services = win32service.EnumServicesStatus(
                    scm_handle,
                    service_type,
                    service_state
                )
                
                for service in services:
                    service_name = service[0]
                    display_name = service[1]
                    service_status = service[2]
                    
                    # Get detailed service config
                    service_info = self._get_service_info(service_name)
                    
                    if service_info and self._is_suspicious(service_info):
                        suspicious_entry = {
                            "id": hashlib.md5(service_name.encode()).hexdigest(),
                            "service_name": service_name,
                            "display_name": display_name,
                            "binary_path": service_info.get("binary_path", "Unknown"),
                            "startup_type": service_info.get("startup_type", "Unknown"),
                            "status": self._get_status_name(service_status[1]),
                            "description": service_info.get("description", ""),
                            "risk_score": self._calculate_risk_score(service_info),
                            "indicators": self._get_indicators(service_info),
                            "dependencies": service_info.get("dependencies", []),
                            "scanned_at": datetime.utcnow().isoformat(),
                        }
                        suspicious_services.append(suspicious_entry)
                
            finally:
                win32service.CloseServiceHandle(scm_handle)
        
        except Exception as e:
            print(f"Error scanning services: {str(e)}")
        
        return suspicious_services
    
    def _get_service_info(self, service_name: str) -> Optional[Dict]:
        """
        Get detailed information about a service
        
        Args:
            service_name: Name of the service
            
        Returns:
            Dictionary with service details or None
        """
        try:
            scm_handle = win32service.OpenSCManager(
                None,
                None,
                win32service.SC_MANAGER_ALL_ACCESS
            )
            
            try:
                service_handle = win32service.OpenService(
                    scm_handle,
                    service_name,
                    win32service.SERVICE_ALL_ACCESS
                )
                
                try:
                    config = win32service.QueryServiceConfig(service_handle)
                    
                    # Parse service config
                    startup_type_map = {
                        win32service.SERVICE_AUTO_START: "Automatic",
                        win32service.SERVICE_BOOT_START: "Boot",
                        win32service.SERVICE_DEMAND_START: "Manual",
                        win32service.SERVICE_DISABLED: "Disabled",
                        win32service.SERVICE_SYSTEM_START: "System",
                    }
                    
                    return {
                        "service_name": service_name,
                        "binary_path": config[3],  # BinaryPathName
                        "startup_type": startup_type_map.get(config[1], "Unknown"),
                        "dependencies": config[6] if config[6] else [],
                        "description": config[8] if len(config) > 8 else "",
                    }
                
                finally:
                    win32service.CloseServiceHandle(service_handle)
            
            finally:
                win32service.CloseServiceHandle(scm_handle)
        
        except Exception as e:
            print(f"Error getting service info for {service_name}: {str(e)}")
            return None
    
    def _is_suspicious(self, service_info: Dict) -> bool:
        """
        Check if a service is suspicious
        
        Args:
            service_info: Service information dictionary
            
        Returns:
            True if suspicious, False otherwise
        """
        service_name = service_info.get("service_name", "").lower()
        binary_path = service_info.get("binary_path", "").lower()
        
        # Check whitelist first
        if service_name in WHITELIST:
            return False
        
        # Check for suspicious patterns in binary path
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern.lower() in binary_path:
                return True
        
        # Check if binary exists
        # Extract actual path from command line
        path = binary_path.split()[0].strip('"')
        if not os.path.exists(path):
            return True
        
        # Check for suspicious startup type
        startup_type = service_info.get("startup_type", "")
        if startup_type in SUSPICIOUS_STARTUP_TYPES:
            # Additional checks for auto-start services
            if any(pattern in binary_path for pattern in SUSPICIOUS_PATTERNS):
                return True
        
        return False
    
    def _calculate_risk_score(self, service_info: Dict) -> int:
        """
        Calculate risk score (0-100) based on suspicious indicators
        
        Args:
            service_info: Service information
            
        Returns:
            Risk score from 0-100
        """
        score = 0
        binary_path = service_info.get("binary_path", "").lower()
        startup_type = service_info.get("startup_type", "")
        
        # High-risk patterns
        high_risk = ["temp", "public", "appdata\\local\\temp", "miner", "crypto"]
        for pattern in high_risk:
            if pattern in binary_path:
                score += 30
        
        # Medium-risk patterns
        medium_risk = ["cmd.exe", "powershell.exe", "wscript.exe", ".bat", ".vbs"]
        for pattern in medium_risk:
            if pattern in binary_path:
                score += 20
        
        # Automatic startup adds risk
        if startup_type == "Automatic":
            score += 15
        
        # Boot-start is very suspicious for non-drivers
        if startup_type == "Boot":
            score += 25
        
        # Binary doesn't exist
        path = binary_path.split()[0].strip('"')
        if not os.path.exists(path):
            score += 30
        
        return min(score, 100)
    
    def _get_indicators(self, service_info: Dict) -> List[str]:
        """
        Get list of suspicious indicators for a service
        
        Args:
            service_info: Service information
            
        Returns:
            List of indicator descriptions
        """
        indicators = []
        binary_path = service_info.get("binary_path", "").lower()
        startup_type = service_info.get("startup_type", "")
        
        if any(p in binary_path for p in ["temp", "public"]):
            indicators.append("Located in temporary/public directory")
        
        if any(p in binary_path for p in ["cmd.exe", "powershell.exe", "wscript.exe"]):
            indicators.append("Uses scripting/command tool")
        
        if any(ext in binary_path for ext in [".bat", ".vbs", ".ps1"]):
            indicators.append("Script-based service")
        
        if startup_type == "Automatic":
            indicators.append("Auto-starts with Windows")
        
        if startup_type == "Boot":
            indicators.append("Boots with system")
        
        path = binary_path.split()[0].strip('"')
        if not os.path.exists(path):
            indicators.append("Binary file not found")
        
        if any(name in binary_path for name in ["miner", "crypto", "keylog"]):
            indicators.append("Suspicious service name")
        
        return indicators
    
    def _get_status_name(self, status_code: int) -> str:
        """Convert service status code to name"""
        status_map = {
            win32service.SERVICE_STOPPED: "Stopped",
            win32service.SERVICE_START_PENDING: "Starting",
            win32service.SERVICE_STOP_PENDING: "Stopping",
            win32service.SERVICE_RUNNING: "Running",
            win32service.SERVICE_CONTINUE_PENDING: "Resuming",
            win32service.SERVICE_PAUSE_PENDING: "Pausing",
            win32service.SERVICE_PAUSED: "Paused",
        }
        return status_map.get(status_code, "Unknown")
    
    def backup_service(self, service_name: str) -> str:
        """
        Backup a service configuration before removal
        
        Args:
            service_name: Name of the service to backup
            
        Returns:
            Path to backup file
        """
        if not self.is_windows:
            return ""
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_id = hashlib.md5(service_name.encode()).hexdigest()[:8]
        backup_file = os.path.join(self.backup_dir, f"service_backup_{timestamp}_{backup_id}.json")
        
        try:
            service_info = self._get_service_info(service_name)
            
            if service_info:
                backup_data = {
                    "service_name": service_name,
                    "binary_path": service_info.get("binary_path", ""),
                    "startup_type": service_info.get("startup_type", ""),
                    "dependencies": service_info.get("dependencies", []),
                    "description": service_info.get("description", ""),
                    "backed_up_at": datetime.utcnow().isoformat(),
                }
                
                with open(backup_file, "w") as f:
                    json.dump(backup_data, f, indent=2)
                
                return backup_file
        
        except Exception as e:
            print(f"Error backing up service: {str(e)}")
            return ""
    
    def stop_service(self, service_name: str) -> Tuple[bool, str]:
        """
        Stop a Windows service
        
        Args:
            service_name: Name of the service
            
        Returns:
            Tuple of (success, message)
        """
        if not self.is_windows:
            return False, "Not a Windows system"
        
        try:
            win32serviceutil.StopService(service_name)
            return True, f"Service '{service_name}' stopped successfully"
        
        except pywintypes.error as e:
            return False, f"Error stopping service: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def delete_service(self, service_name: str) -> Tuple[bool, str]:
        """
        Delete a Windows service (with automatic backup)
        
        Args:
            service_name: Name of the service to delete
            
        Returns:
            Tuple of (success, message/backup_file)
        """
        if not self.is_windows:
            return False, "Not a Windows system"
        
        # Backup first
        backup_file = self.backup_service(service_name)
        if not backup_file:
            return False, "Failed to create backup"
        
        try:
            # Stop service first
            try:
                win32serviceutil.StopService(service_name)
            except:
                pass  # Service might already be stopped
            
            # Delete service
            scm_handle = win32service.OpenSCManager(
                None,
                None,
                win32service.SC_MANAGER_ALL_ACCESS
            )
            
            try:
                service_handle = win32service.OpenService(
                    scm_handle,
                    service_name,
                    win32service.SERVICE_ALL_ACCESS
                )
                
                try:
                    win32service.DeleteService(service_handle)
                    return True, backup_file
                
                finally:
                    win32service.CloseServiceHandle(service_handle)
            
            finally:
                win32service.CloseServiceHandle(scm_handle)
        
        except pywintypes.error as e:
            return False, f"Permission denied - run as administrator: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def get_statistics(self, services: List[Dict]) -> Dict:
        """
        Get statistics from scan results
        
        Args:
            services: List of suspicious services
            
        Returns:
            Statistics dictionary
        """
        if not services:
            return {
                "total_suspicious": 0,
                "critical_risk": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "by_status": {},
                "by_startup_type": {},
            }
        
        stats = {
            "total_suspicious": len(services),
            "critical_risk": len([s for s in services if s["risk_score"] >= 80]),
            "high_risk": len([s for s in services if 60 <= s["risk_score"] < 80]),
            "medium_risk": len([s for s in services if 40 <= s["risk_score"] < 60]),
            "low_risk": len([s for s in services if s["risk_score"] < 40]),
            "by_status": {},
            "by_startup_type": {},
        }
        
        # Count by status
        for service in services:
            status = service["status"]
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
        
        # Count by startup type
        for service in services:
            startup = service["startup_type"]
            stats["by_startup_type"][startup] = stats["by_startup_type"].get(startup, 0) + 1
        
        return stats


# Standalone functions for database integration
def scan_windows_services() -> List[Dict]:
    """Scan Windows services for suspicious entries"""
    manager = ServiceManager()
    return manager.scan_services()


def stop_windows_service(service_name: str) -> Tuple[bool, str]:
    """Stop a Windows service"""
    manager = ServiceManager()
    return manager.stop_service(service_name)


def delete_windows_service(service_name: str) -> Tuple[bool, str]:
    """Delete a Windows service with backup"""
    manager = ServiceManager()
    return manager.delete_service(service_name)


def get_service_statistics(services: List[Dict]) -> Dict:
    """Get statistics from service scan"""
    manager = ServiceManager()
    return manager.get_statistics(services)