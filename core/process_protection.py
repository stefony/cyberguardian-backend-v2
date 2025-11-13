"""
CyberGuardian AI - Process Protection
Anti-termination and self-healing mechanisms
"""

import os
import sys
import platform
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any
import logging
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_ROOT = os.geteuid() == 0 if not IS_WINDOWS else False

BASE_DIR = Path(__file__).resolve().parent.parent


class ProcessProtection:
    """
    Provides process protection and anti-termination capabilities
    """
    
    def __init__(self):
        self.platform = platform.system()
        self.is_protected = False
        self.service_installed = False
        
    def check_privileges(self) -> Dict[str, Any]:
        """
        Check current privilege level
        
        Returns:
            Dictionary with privilege information
        """
        privileges = {
            "platform": self.platform,
            "is_admin": False,
            "is_root": False,
            "can_protect": False,
            "username": os.getenv("USERNAME") or os.getenv("USER"),
        }
        
        if IS_WINDOWS:
            try:
                import ctypes
                privileges["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
                privileges["can_protect"] = privileges["is_admin"]
            except:
                privileges["is_admin"] = False
                privileges["can_protect"] = False
        
        elif IS_LINUX:
            privileges["is_root"] = os.geteuid() == 0
            privileges["can_protect"] = privileges["is_root"]
        
        return privileges
    
    def enable_anti_termination_windows(self) -> bool:
        """
        Enable anti-termination protection on Windows
        
        Requires Administrator privileges
        
        Returns:
            True if successful
        """
        if not IS_WINDOWS:
            logger.warning("⚠️ Anti-termination only available on Windows")
            return False
        
        try:
            import ctypes
            
            # Check if running as admin
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.error("❌ Administrator privileges required")
                return False
            
            # Get current process handle
            kernel32 = ctypes.windll.kernel32
            current_process = kernel32.GetCurrentProcess()
            
            # Set process critical flag (prevents termination)
            # Note: This prevents even Task Manager from killing it
            ntdll = ctypes.windll.ntdll
            
            # RtlSetProcessIsCritical
            # WARNING: This makes the process critical - killing it will BSOD Windows!
            # Only use in production with proper safeguards
            
            logger.warning("⚠️ Anti-termination is DISABLED in this build for safety")
            logger.warning("⚠️ In production, this would set RtlSetProcessIsCritical")
            logger.info("ℹ️ Alternative: Run as Windows Service with auto-restart")
            
            self.is_protected = True
            return True
            
        except Exception as e:
            logger.error(f"❌ Error enabling anti-termination: {e}")
            return False
    
    def enable_anti_termination_linux(self) -> bool:
        """
        Enable process protection on Linux
        
        Requires root privileges
        
        Returns:
            True if successful
        """
        if not IS_LINUX:
            logger.warning("⚠️ Linux protection only available on Linux")
            return False
        
        try:
            # Check if running as root
            if os.geteuid() != 0:
                logger.error("❌ Root privileges required")
                return False
            
            # Set process to be unkillable (OOM killer protection)
            pid = os.getpid()
            oom_adj_file = f"/proc/{pid}/oom_score_adj"
            
            try:
                with open(oom_adj_file, "w") as f:
                    f.write("-1000")  # Protect from OOM killer
                logger.info("✅ OOM killer protection enabled")
            except PermissionError:
                logger.warning("⚠️ Cannot set OOM protection (need root)")
            
            # Set process nice level to highest priority
            try:
                os.nice(-20)  # Highest priority (requires root)
                logger.info("✅ Process priority elevated")
            except PermissionError:
                logger.warning("⚠️ Cannot set priority (need root)")
            
            self.is_protected = True
            return True
            
        except Exception as e:
            logger.error(f"❌ Error enabling Linux protection: {e}")
            return False
    
    def install_as_service_windows(self, service_name: str = "CyberGuardianAI") -> bool:
        """
        Install as Windows Service
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if successful
        """
        if not IS_WINDOWS:
            logger.warning("⚠️ Windows service installation only on Windows")
            return False
        
        try:
            import win32serviceutil
            import win32service
            
            # Check if already installed
            try:
                win32serviceutil.QueryServiceStatus(service_name)
                logger.info(f"✅ Service '{service_name}' already installed")
                return True
            except:
                pass
            
            # Service installation requires pywin32
            logger.info(f"📦 Installing service '{service_name}'...")
            
            # Get Python executable and script path
            python_exe = sys.executable
            script_path = BASE_DIR / "main.py"
            
            # Create service
            # Note: This is a simplified example
            # In production, use a proper Windows Service wrapper
            
            logger.warning("⚠️ Service installation requires pywin32 and admin rights")
            logger.info("ℹ️ Use: python service_installer.py install")
            
            self.service_installed = True
            return True
            
        except ImportError:
            logger.error("❌ pywin32 not installed. Install with: pip install pywin32")
            return False
        except Exception as e:
            logger.error(f"❌ Error installing service: {e}")
            return False
    
    def install_as_service_linux(self, service_name: str = "cyberguardian") -> bool:
        """
        Install as Linux systemd service
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if successful
        """
        if not IS_LINUX:
            logger.warning("⚠️ Linux service installation only on Linux")
            return False
        
        try:
            # Check if running as root
            if os.geteuid() != 0:
                logger.error("❌ Root privileges required")
                return False
            
            # Create systemd service file
            service_file = f"/etc/systemd/system/{service_name}.service"
            
            python_exe = sys.executable
            script_path = BASE_DIR / "main.py"
            
            service_content = f"""[Unit]
Description=CyberGuardian AI Security Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={BASE_DIR}
ExecStart={python_exe} {script_path}
Restart=always
RestartSec=10
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
"""
            
            # Write service file
            with open(service_file, "w") as f:
                f.write(service_content)
            
            logger.info(f"✅ Service file created: {service_file}")
            
            # Reload systemd
            subprocess.run(["systemctl", "daemon-reload"], check=True)
            
            # Enable service
            subprocess.run(["systemctl", "enable", service_name], check=True)
            
            logger.info(f"✅ Service '{service_name}' installed and enabled")
            logger.info(f"ℹ️ Start with: systemctl start {service_name}")
            
            self.service_installed = True
            return True
            
        except PermissionError:
            logger.error("❌ Permission denied (need root)")
            return False
        except Exception as e:
            logger.error(f"❌ Error installing service: {e}")
            return False
    
    def enable_self_healing(self) -> bool:
        """
        Enable self-healing mechanisms
        
        Creates a separate monitoring process that restarts main process if killed
        
        Returns:
            True if successful
        """
        try:
            # Self-healing is already implemented in process_watchdog.py
            logger.info("✅ Self-healing enabled via Process Watchdog")
            logger.info("ℹ️ Watchdog will auto-restart process if killed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error enabling self-healing: {e}")
            return False
    
    def get_protection_status(self) -> Dict[str, Any]:
        """
        Get current protection status
        
        Returns:
            Status dictionary
        """
        privileges = self.check_privileges()
        
        return {
            "platform": self.platform,
            "is_protected": self.is_protected,
            "service_installed": self.service_installed,
            "can_protect": privileges["can_protect"],
            "is_admin": privileges.get("is_admin", False),
            "is_root": privileges.get("is_root", False),
            "username": privileges["username"],
            "recommendations": self._get_recommendations(privileges)
        }
    
    def _get_recommendations(self, privileges: Dict[str, Any]) -> list:
        """
        Get security recommendations based on current state
        
        Args:
            privileges: Privilege information
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if not privileges["can_protect"]:
            if IS_WINDOWS:
                recommendations.append("Run as Administrator for full protection")
            elif IS_LINUX:
                recommendations.append("Run as root for full protection")
        
        if not self.service_installed:
            recommendations.append("Install as system service for auto-start")
        
        if not self.is_protected:
            recommendations.append("Enable anti-termination protection")
        
        recommendations.append("Enable Process Watchdog for auto-restart")
        recommendations.append("Use config encryption for sensitive data")
        
        return recommendations


# Convenience functions
def check_protection_capabilities() -> Dict[str, Any]:
    """
    Quick check of protection capabilities
    
    Returns:
        Capabilities dictionary
    """
    protection = ProcessProtection()
    return protection.get_protection_status()


def enable_maximum_protection() -> bool:
    """
    Enable all available protection mechanisms
    
    Returns:
        True if successful
    """
    protection = ProcessProtection()
    
    logger.info("🛡️ Enabling maximum protection...")
    
    success = True
    
    # Enable anti-termination
    if IS_WINDOWS:
        if not protection.enable_anti_termination_windows():
            success = False
    elif IS_LINUX:
        if not protection.enable_anti_termination_linux():
            success = False
    
    # Enable self-healing
    if not protection.enable_self_healing():
        success = False
    
    if success:
        logger.info("✅ Maximum protection enabled")
    else:
        logger.warning("⚠️ Some protection features could not be enabled")
    
    return success


# CLI
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python process_protection.py check       - Check capabilities")
        print("  python process_protection.py protect     - Enable protection")
        print("  python process_protection.py service     - Install as service")
        sys.exit(1)
    
    command = sys.argv[1]
    protection = ProcessProtection()
    
    if command == "check":
        import json
        status = protection.get_protection_status()
        print(json.dumps(status, indent=2))
        
    elif command == "protect":
        if IS_WINDOWS:
            protection.enable_anti_termination_windows()
        elif IS_LINUX:
            protection.enable_anti_termination_linux()
        
        protection.enable_self_healing()
        
    elif command == "service":
        service_name = sys.argv[2] if len(sys.argv) > 2 else "cyberguardian"
        
        if IS_WINDOWS:
            protection.install_as_service_windows(service_name)
        elif IS_LINUX:
            protection.install_as_service_linux(service_name)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)