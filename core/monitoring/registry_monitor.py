"""
CyberGuardian - Windows Registry Monitor
=========================================

Real-time Windows Registry monitoring for threat detection.

Monitors:
- Registry key creation, modification, deletion
- Autorun/persistence mechanisms
- Security setting changes
- System configuration tampering
- Scheduled tasks via registry
- Service modifications

Detection capabilities:
- Persistence establishment (AutoRun keys)
- Security bypass (UAC, Defender, Firewall)
- Browser hijacking
- Credential stealing attempts
- System file replacement
- Boot sector modifications
- DLL hijacking setup

Platform support:
- Windows only (WMI + Registry API)

MITRE ATT&CK Coverage:
- T1547: Boot or Logon Autostart Execution
- T1112: Modify Registry
- T1546: Event Triggered Execution
- T1562: Impair Defenses
- T1553: Subvert Trust Controls

Critical Registry Keys:
- HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM\System\CurrentControlSet\Services
- HKLM\Software\Microsoft\Windows Defender
"""

import os
import sys
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

# Windows-specific imports
if sys.platform == 'win32':
    try:
        import winreg
        WINREG_AVAILABLE = True
    except ImportError:
        WINREG_AVAILABLE = False
        logging.warning("winreg not available")
    
    try:
        import wmi
        WMI_AVAILABLE = True
    except ImportError:
        WMI_AVAILABLE = False
        logging.warning("WMI not available - some features disabled")
else:
    WINREG_AVAILABLE = False
    WMI_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

class RegistryEventType(Enum):
    """Registry event types"""
    KEY_CREATED = "key_created"
    KEY_DELETED = "key_deleted"
    VALUE_SET = "value_set"
    VALUE_DELETED = "value_deleted"


class ThreatLevel(Enum):
    """Threat level for registry events"""
    BENIGN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class RegistryEvent:
    """
    Information about a registry event.
    
    Attributes:
        event_type: Type of registry event
        hive: Registry hive (HKLM, HKCU, etc.)
        key_path: Full key path
        value_name: Value name (if applicable)
        value_data: Value data (if applicable)
        timestamp: When event occurred
        threat_level: Assessed threat level
        threat_reasons: Why this is suspicious
        mitre_techniques: MITRE ATT&CK techniques
    """
    event_type: RegistryEventType
    hive: str
    key_path: str
    value_name: Optional[str] = None
    value_data: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    threat_reasons: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


# ============================================================================
# REGISTRY MONITOR
# ============================================================================

class RegistryMonitor:
    """
    Windows Registry monitor with threat detection.
    
    Monitors critical registry locations for malicious activity.
    """
    
    # Critical registry paths to monitor (persistence mechanisms)
    CRITICAL_PATHS = {
        # Autorun locations
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run': 'Autorun',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce': 'Autorun (Once)',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices': 'Autorun Services',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce': 'Autorun Services (Once)',
        r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run': 'Autorun (32-bit)',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders': 'Shell Folders',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders': 'User Shell Folders',
        
        # Services
        r'SYSTEM\CurrentControlSet\Services': 'Services',
        
        # Security settings
        r'SOFTWARE\Microsoft\Windows Defender': 'Windows Defender',
        r'SOFTWARE\Policies\Microsoft\Windows Defender': 'Defender Policies',
        r'SYSTEM\CurrentControlSet\Control\SecurityProviders': 'Security Providers',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies': 'Group Policies',
        
        # System configuration
        r'SYSTEM\CurrentControlSet\Control\Session Manager': 'Session Manager',
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon': 'Winlogon',
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows': 'Windows Settings',
        
        # Network settings
        r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters': 'TCP/IP Settings',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings': 'Internet Settings',
        
        # Browser hijacking
        r'SOFTWARE\Microsoft\Internet Explorer\Main': 'IE Main Settings',
        r'SOFTWARE\Microsoft\Internet Explorer\Search': 'IE Search Settings',
    }
    
    # Registry hive mappings
    HIVES = {
        'HKLM': winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
        'HKCU': winreg.HKEY_CURRENT_USER if WINREG_AVAILABLE else None,
        'HKCR': winreg.HKEY_CLASSES_ROOT if WINREG_AVAILABLE else None,
        'HKU': winreg.HKEY_USERS if WINREG_AVAILABLE else None,
        'HKCC': winreg.HKEY_CURRENT_CONFIG if WINREG_AVAILABLE else None,
    }
    
    # Suspicious value names
    SUSPICIOUS_VALUE_NAMES = {
        'debugger',  # Image File Execution Options debugging
        'disablerealtimemonitoring',  # Defender
        'disablebehaviormonitoring',  # Defender
        'disableonaccessprotection',  # Defender
        'disablescanonrealtimeenable',  # Defender
        'userinit',  # Persistence via Winlogon
        'shell',  # Persistence via Winlogon
        'appinit_dlls',  # DLL injection
    }
    
    # Suspicious executable extensions
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.com'
    }
    
    def __init__(self, 
                 callback: Optional[Callable[[RegistryEvent], None]] = None,
                 scan_interval: float = 10.0):
        """
        Initialize registry monitor.
        
        Args:
            callback: Function to call when suspicious change detected
            scan_interval: Seconds between registry scans
        """
        if not WINREG_AVAILABLE:
            raise RuntimeError("Registry monitoring requires Windows platform")
        
        self.callback = callback
        self.scan_interval = scan_interval
        
        self.logger = logging.getLogger(__name__)
        
        # Baseline storage (key -> {value_name: value_data})
        self.baseline: Dict[str, Dict[str, str]] = {}
        
        # Statistics
        self.events_detected = 0
        self.suspicious_events = 0
        self.start_time = None
        
        # Threading
        self.running = False
        self.monitor_thread = None
    
    # ========================================================================
    # MONITORING CONTROL
    # ========================================================================
    
    def start(self):
        """Start monitoring registry"""
        self.logger.info("Starting registry monitor...")
        self.start_time = datetime.now()
        self.running = True
        
        # Create baseline
        self.logger.info("Creating registry baseline...")
        self._create_baseline()
        self.logger.info(f"Baseline created: {len(self.baseline)} keys")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("Registry monitor started")
    
    def stop(self):
        """Stop monitoring"""
        self.logger.info("Stopping registry monitor...")
        self.running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Registry monitor stopped")
        self._print_statistics()
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._check_changes()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                time.sleep(1)
    
    def _print_statistics(self):
        """Print monitoring statistics"""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"""
            === Registry Monitor Statistics ===
            Runtime: {duration:.1f} seconds
            Events detected: {self.events_detected}
            Suspicious events: {self.suspicious_events}
            Monitored keys: {len(self.baseline)}
            """)
    
    # ========================================================================
    # BASELINE CREATION
    # ========================================================================
    
    def _create_baseline(self):
        """Create baseline of critical registry keys"""
        for hive_name in ['HKLM', 'HKCU']:
            hive = self.HIVES[hive_name]
            
            for key_path in self.CRITICAL_PATHS.keys():
                try:
                    values = self._read_registry_key(hive, key_path)
                    full_path = f"{hive_name}\\{key_path}"
                    self.baseline[full_path] = values
                except Exception as e:
                    self.logger.debug(f"Could not read {hive_name}\\{key_path}: {e}")
    
    def _read_registry_key(self, hive, key_path: str) -> Dict[str, str]:
        """
        Read all values in a registry key.
        
        Returns:
            dict: {value_name: value_data}
        """
        values = {}
        
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, index)
                        values[value_name] = str(value_data)
                        index += 1
                    except OSError:
                        break  # No more values
        except FileNotFoundError:
            pass  # Key doesn't exist
        except PermissionError:
            self.logger.debug(f"Permission denied reading {key_path}")
        
        return values
    
    # ========================================================================
    # CHANGE DETECTION
    # ========================================================================
    
    def _check_changes(self):
        """Check for registry changes"""
        for full_path in list(self.baseline.keys()):
            try:
                # Parse hive and key path
                hive_name, key_path = full_path.split('\\', 1)
                hive = self.HIVES[hive_name]
                
                # Read current values
                current_values = self._read_registry_key(hive, key_path)
                baseline_values = self.baseline[full_path]
                
                # Detect changes
                self._detect_value_changes(
                    hive_name, 
                    key_path, 
                    baseline_values, 
                    current_values
                )
                
                # Update baseline
                self.baseline[full_path] = current_values
                
            except Exception as e:
                self.logger.debug(f"Error checking {full_path}: {e}")
    
    def _detect_value_changes(self, 
                             hive: str, 
                             key_path: str,
                             baseline: Dict[str, str],
                             current: Dict[str, str]):
        """Detect changes between baseline and current values"""
        
        # New values
        for value_name in set(current.keys()) - set(baseline.keys()):
            self._handle_new_value(
                hive, 
                key_path, 
                value_name, 
                current[value_name]
            )
        
        # Modified values
        for value_name in set(current.keys()) & set(baseline.keys()):
            if current[value_name] != baseline[value_name]:
                self._handle_modified_value(
                    hive,
                    key_path,
                    value_name,
                    baseline[value_name],
                    current[value_name]
                )
        
        # Deleted values
        for value_name in set(baseline.keys()) - set(current.keys()):
            self._handle_deleted_value(
                hive,
                key_path,
                value_name
            )
    
    # ========================================================================
    # EVENT HANDLERS
    # ========================================================================
    
    def _handle_new_value(self, hive: str, key_path: str, value_name: str, value_data: str):
        """Handle new registry value"""
        self.events_detected += 1
        
        event = RegistryEvent(
            event_type=RegistryEventType.VALUE_SET,
            hive=hive,
            key_path=key_path,
            value_name=value_name,
            value_data=value_data
        )
        
        # Analyze threat
        self._analyze_event(event)
        
        # Alert if suspicious
        if event.threat_level.value >= ThreatLevel.MEDIUM.value:
            self.suspicious_events += 1
            self._alert_suspicious_event(event)
    
    def _handle_modified_value(self, 
                               hive: str, 
                               key_path: str, 
                               value_name: str,
                               old_data: str,
                               new_data: str):
        """Handle modified registry value"""
        self.events_detected += 1
        
        event = RegistryEvent(
            event_type=RegistryEventType.VALUE_SET,
            hive=hive,
            key_path=key_path,
            value_name=value_name,
            value_data=new_data
        )
        
        # Analyze threat
        self._analyze_event(event)
        
        # Alert if suspicious
        if event.threat_level.value >= ThreatLevel.MEDIUM.value:
            self.suspicious_events += 1
            self.logger.warning(
                f"Registry value modified: {hive}\\{key_path}\\{value_name}\n"
                f"  Old: {old_data}\n"
                f"  New: {new_data}"
            )
            self._alert_suspicious_event(event)
    
    def _handle_deleted_value(self, hive: str, key_path: str, value_name: str):
        """Handle deleted registry value"""
        self.events_detected += 1
        
        event = RegistryEvent(
            event_type=RegistryEventType.VALUE_DELETED,
            hive=hive,
            key_path=key_path,
            value_name=value_name
        )
        
        # Analyze threat
        self._analyze_event(event)
        
        # Alert if suspicious
        if event.threat_level.value >= ThreatLevel.MEDIUM.value:
            self.suspicious_events += 1
            self._alert_suspicious_event(event)
    
    # ========================================================================
    # THREAT ANALYSIS
    # ========================================================================
    
    def _analyze_event(self, event: RegistryEvent):
        """
        Analyze registry event for suspicious activity.
        
        Updates event with threat_level, threat_reasons, and mitre_techniques.
        """
        threat_level = ThreatLevel.BENIGN
        reasons = []
        mitre_techniques = []
        
        key_path_lower = event.key_path.lower()
        value_name_lower = event.value_name.lower() if event.value_name else ''
        value_data_lower = event.value_data.lower() if event.value_data else ''
        
        # Check 1: Autorun/Persistence
        if 'run' in key_path_lower and 'currentversion' in key_path_lower:
            reasons.append("Autorun persistence location")
            threat_level = max(threat_level, ThreatLevel.HIGH)
            mitre_techniques.append("T1547.001")  # Registry Run Keys
        
        # Check 2: Windows Defender tampering
        if 'windows defender' in key_path_lower:
            if 'disable' in value_name_lower:
                reasons.append("Windows Defender setting modification")
                threat_level = ThreatLevel.CRITICAL
                mitre_techniques.append("T1562.001")  # Disable or Modify Tools
        
        # Check 3: Suspicious value names
        for suspicious in self.SUSPICIOUS_VALUE_NAMES:
            if suspicious in value_name_lower:
                reasons.append(f"Suspicious value name: {suspicious}")
                threat_level = max(threat_level, ThreatLevel.HIGH)
                mitre_techniques.append("T1112")  # Modify Registry
        
        # Check 4: Executable in autorun
        if event.value_data:
            for ext in self.SUSPICIOUS_EXTENSIONS:
                if ext in value_data_lower:
                    # Check if in temp or suspicious location
                    if any(x in value_data_lower for x in ['temp', 'tmp', 'appdata']):
                        reasons.append(f"Suspicious executable path: {ext}")
                        threat_level = max(threat_level, ThreatLevel.HIGH)
                        mitre_techniques.append("T1547")  # Boot or Logon Autostart
                    break
        
        # Check 5: Service creation/modification
        if 'services' in key_path_lower and event.event_type == RegistryEventType.VALUE_SET:
            reasons.append("Service registry modification")
            threat_level = max(threat_level, ThreatLevel.MEDIUM)
            mitre_techniques.append("T1543.003")  # Windows Service
        
        # Check 6: Security provider modification
        if 'securityproviders' in key_path_lower:
            reasons.append("Security provider modification")
            threat_level = ThreatLevel.CRITICAL
            mitre_techniques.append("T1556")  # Modify Authentication Process
        
        # Check 7: Internet settings tampering
        if 'internet settings' in key_path_lower:
            reasons.append("Internet settings modification")
            threat_level = max(threat_level, ThreatLevel.MEDIUM)
            mitre_techniques.append("T1112")  # Modify Registry
        
        # Check 8: Winlogon modification
        if 'winlogon' in key_path_lower:
            reasons.append("Winlogon modification (persistence)")
            threat_level = ThreatLevel.CRITICAL
            mitre_techniques.append("T1547.004")  # Winlogon Helper DLL
        
        # Update event
        event.threat_level = threat_level
        event.threat_reasons = reasons
        event.mitre_techniques = list(set(mitre_techniques))
    
    # ========================================================================
    # ALERTING
    # ========================================================================
    
    def _alert_suspicious_event(self, event: RegistryEvent):
        """Alert about suspicious registry change"""
        self.logger.warning(
            f"\n🚨 [{event.threat_level.name}] Suspicious Registry Change!\n"
            f"   Type: {event.event_type.value}\n"
            f"   Path: {event.hive}\\{event.key_path}\n"
            f"   Value: {event.value_name}\n"
            f"   Data: {event.value_data}\n"
            f"   Reasons: {', '.join(event.threat_reasons)}\n"
            f"   MITRE: {', '.join(event.mitre_techniques)}\n"
        )
        
        # Callback
        if self.callback:
            try:
                self.callback(event)
            except Exception as e:
                self.logger.error(f"Error in callback: {e}")


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def start_monitoring(callback: Optional[Callable[[RegistryEvent], None]] = None,
                    scan_interval: float = 10.0) -> Optional[RegistryMonitor]:
    """
    Start monitoring Windows registry.
    
    Args:
        callback: Function to call on suspicious change
        scan_interval: Seconds between scans
        
    Returns:
        RegistryMonitor: Monitor instance or None if not on Windows
    """
    if not WINREG_AVAILABLE:
        logging.warning("Registry monitoring only available on Windows")
        return None
    
    monitor = RegistryMonitor(callback, scan_interval)
    monitor.start()
    return monitor


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    if not WINREG_AVAILABLE:
        print("❌ Registry monitoring requires Windows platform")
        sys.exit(1)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("📝 CyberGuardian Registry Monitor - Demo\n")
    
    # Callback for suspicious events
    def alert_callback(event: RegistryEvent):
        print(f"\n{'='*60}")
        print(f"⚠️  REGISTRY ALERT!")
        print(f"{'='*60}")
        print(f"Type: {event.event_type.value}")
        print(f"Key: {event.hive}\\{event.key_path}")
        print(f"Value: {event.value_name}")
        print(f"Data: {event.value_data}")
        print(f"Threat: {event.threat_level.name}")
        print(f"Reasons: {', '.join(event.threat_reasons)}")
        print(f"{'='*60}\n")
    
    # Start monitoring
    monitor = start_monitoring(callback=alert_callback, scan_interval=5.0)
    
    if monitor:
        print("Monitoring critical registry keys...")
        print("Make registry changes to see detection in action")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nStopping monitor...")
            monitor.stop()
            print("✅ Monitor stopped")
    else:
        print("❌ Could not start monitor")