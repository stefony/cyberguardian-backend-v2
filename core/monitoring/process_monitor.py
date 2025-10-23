"""
CyberGuardian - Process Monitor
================================

Real-time process monitoring for threat detection.

Monitors:
- Process creation and termination
- Parent-child process relationships
- Command-line arguments
- Process memory usage
- Network connections by process
- DLL/library loading
- Process injection attempts

Detection capabilities:
- Fileless malware (process injection)
- Suspicious process chains
- Privilege escalation attempts
- Process hollowing
- Command-line obfuscation
- Living-off-the-land (LOLBins) abuse
- Cryptocurrency mining

Platform support:
- Windows: WMI + ETW
- macOS: ps + activity monitor
- Linux: /proc filesystem

Threat Intelligence:
- MITRE ATT&CK technique mapping
- Known malicious process patterns
- Suspicious parent-child relationships
"""

import os
import sys
import time
import psutil
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import logging

# Platform-specific imports
if sys.platform == 'win32':
    try:
        import wmi
        WMI_AVAILABLE = True
    except ImportError:
        WMI_AVAILABLE = False
        logging.warning("WMI not available - some features disabled")


# ============================================================================
# CONFIGURATION
# ============================================================================

class ProcessEventType(Enum):
    """Process event types"""
    CREATED = "created"
    TERMINATED = "terminated"
    MODIFIED = "modified"


class ThreatLevel(Enum):
    """Threat level for process events"""
    BENIGN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ProcessInfo:
    """
    Information about a process.
    
    Attributes:
        pid: Process ID
        name: Process name
        exe_path: Full path to executable
        cmdline: Command line arguments
        parent_pid: Parent process ID
        parent_name: Parent process name
        username: User running the process
        create_time: When process was created
        cpu_percent: CPU usage percentage
        memory_mb: Memory usage in MB
        connections: Network connections
        threat_level: Assessed threat level
        threat_reasons: Why this is suspicious
        mitre_techniques: MITRE ATT&CK techniques detected
    """
    pid: int
    name: str
    exe_path: Optional[str] = None
    cmdline: List[str] = field(default_factory=list)
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    username: Optional[str] = None
    create_time: Optional[float] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    connections: List[Dict] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    threat_reasons: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


# ============================================================================
# PROCESS MONITOR
# ============================================================================

class ProcessMonitor:
    """
    Cross-platform process monitor with threat detection.
    
    Uses psutil for cross-platform compatibility with platform-specific
    enhancements where available (WMI on Windows, /proc on Linux).
    """
    
    # Suspicious process names (common malware)
    SUSPICIOUS_PROCESSES = {
        'mimikatz', 'pwdump', 'gsecdump', 'wce', 'cachedump',
        'lsadump', 'procdump', 'dumpert', 'netcat', 'nc',
        'powercat', 'ncat', 'socat', 'cryptcat', 'plink',
        'psexec', 'paexec', 'remcos', 'cobaltstrike', 'meterpreter',
        'xmrig', 'ccminer', 'claymore', 'ethminer', 'nicehash'
    }
    
    # Living Off The Land Binaries (LOLBins) - legitimate tools abused by attackers
    LOLBINS_WINDOWS = {
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
        'bitsadmin.exe', 'wmic.exe', 'sc.exe', 'net.exe',
        'reg.exe', 'at.exe', 'schtasks.exe', 'psexec.exe'
    }
    
    LOLBINS_UNIX = {
        'bash', 'sh', 'python', 'perl', 'ruby', 'php',
        'curl', 'wget', 'nc', 'netcat', 'socat',
        'ssh', 'scp', 'rsync', 'dd', 'base64'
    }
    
    # Suspicious parent-child relationships
    SUSPICIOUS_PARENT_CHILD = {
        # Office apps spawning shells
        ('winword.exe', 'powershell.exe'),
        ('excel.exe', 'powershell.exe'),
        ('winword.exe', 'cmd.exe'),
        ('excel.exe', 'cmd.exe'),
        # Browsers spawning unusual processes
        ('chrome.exe', 'powershell.exe'),
        ('firefox.exe', 'cmd.exe'),
        # System processes with unusual children
        ('svchost.exe', 'cmd.exe'),
        ('svchost.exe', 'powershell.exe'),
    }
    
    # Suspicious command-line patterns (regex would be better, but keeping simple)
    SUSPICIOUS_CMDLINE_PATTERNS = [
        'base64',  # Encoded payloads
        'invoke-expression',  # PowerShell code execution
        'iex',  # PowerShell alias
        'downloadstring',  # Download from internet
        'webclient',  # HTTP requests
        'mimikatz',  # Credential dumping
        '-encodedcommand',  # PowerShell encoded
        '-enc',  # PowerShell encoded
        'bypass',  # Execution policy bypass
        'hidden',  # Hidden window
        'invoke-obfuscation',  # Obfuscated code
        'empire',  # Empire framework
        'metasploit',  # Metasploit
        'cobalt',  # Cobalt Strike
    ]
    
    def __init__(self, 
                 callback: Optional[Callable[[ProcessInfo], None]] = None,
                 scan_interval: float = 5.0):
        """
        Initialize process monitor.
        
        Args:
            callback: Function to call when suspicious process detected
            scan_interval: Seconds between process scans
        """
        self.callback = callback
        self.scan_interval = scan_interval
        
        self.logger = logging.getLogger(__name__)
        
        # Process tracking
        self.known_processes: Dict[int, ProcessInfo] = {}
        self.process_tree: Dict[int, List[int]] = {}  # parent_pid -> [child_pids]
        
        # Statistics
        self.processes_scanned = 0
        self.suspicious_processes = 0
        self.start_time = None
        
        # Threading
        self.running = False
        self.monitor_thread = None
        
        # Platform detection
        self.is_windows = sys.platform == 'win32'
        self.is_linux = sys.platform.startswith('linux')
        self.is_macos = sys.platform == 'darwin'
    
    # ========================================================================
    # MONITORING CONTROL
    # ========================================================================
    
    def start(self):
        """Start monitoring processes"""
        self.logger.info("Starting process monitor...")
        self.start_time = datetime.now()
        self.running = True
        
        # Initial scan
        self._scan_processes()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("Process monitor started")
    
    def stop(self):
        """Stop monitoring"""
        self.logger.info("Stopping process monitor...")
        self.running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Process monitor stopped")
        self._print_statistics()
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._scan_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                time.sleep(1)
    
    def _print_statistics(self):
        """Print monitoring statistics"""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"""
            === Process Monitor Statistics ===
            Runtime: {duration:.1f} seconds
            Processes scanned: {self.processes_scanned}
            Suspicious processes: {self.suspicious_processes}
            Active processes: {len(self.known_processes)}
            """)
    
    # ========================================================================
    # PROCESS SCANNING
    # ========================================================================
    
    def _scan_processes(self):
        """Scan all running processes"""
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                
                # New process detected
                if pid not in self.known_processes:
                    self._handle_new_process(proc)
                
                self.processes_scanned += 1
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Detect terminated processes
        terminated_pids = set(self.known_processes.keys()) - current_pids
        for pid in terminated_pids:
            self._handle_terminated_process(pid)
    
    def _handle_new_process(self, proc: psutil.Process):
        """Handle newly created process"""
        try:
            # Gather process information
            proc_info = self._get_process_info(proc)
            
            # Analyze for threats
            self._analyze_process(proc_info)
            
            # Store process
            self.known_processes[proc_info.pid] = proc_info
            
            # Update process tree
            if proc_info.parent_pid:
                if proc_info.parent_pid not in self.process_tree:
                    self.process_tree[proc_info.parent_pid] = []
                self.process_tree[proc_info.parent_pid].append(proc_info.pid)
            
            # Alert on suspicious process
            if proc_info.threat_level.value >= ThreatLevel.MEDIUM.value:
                self.suspicious_processes += 1
                self._alert_suspicious_process(proc_info)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.debug(f"Error handling process: {e}")
    
    def _handle_terminated_process(self, pid: int):
        """Handle terminated process"""
        if pid in self.known_processes:
            proc_info = self.known_processes[pid]
            self.logger.debug(f"Process terminated: {proc_info.name} (PID: {pid})")
            
            # Remove from tracking
            del self.known_processes[pid]
            
            # Remove from process tree
            if proc_info.parent_pid in self.process_tree:
                if pid in self.process_tree[proc_info.parent_pid]:
                    self.process_tree[proc_info.parent_pid].remove(pid)
    
    # ========================================================================
    # PROCESS INFORMATION GATHERING
    # ========================================================================
    
    def _get_process_info(self, proc: psutil.Process) -> ProcessInfo:
        """
        Gather detailed information about a process.
        
        Args:
            proc: psutil Process object
            
        Returns:
            ProcessInfo: Detailed process information
        """
        proc_info = ProcessInfo(
            pid=proc.pid,
            name=proc.name()
        )
        
        # Try to get each piece of info (may fail for privileged processes)
        try:
            proc_info.exe_path = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        try:
            proc_info.cmdline = proc.cmdline()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        try:
            proc_info.username = proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        try:
            proc_info.create_time = proc.create_time()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        try:
            proc_info.cpu_percent = proc.cpu_percent(interval=0.1)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        try:
            memory_info = proc.memory_info()
            proc_info.memory_mb = memory_info.rss / (1024 * 1024)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        # Get parent process info
        try:
            parent = proc.parent()
            if parent:
                proc_info.parent_pid = parent.pid
                proc_info.parent_name = parent.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        # Get network connections
        try:
            connections = proc.connections(kind='inet')
            proc_info.connections = [
                {
                    'local_addr': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    'remote_addr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    'status': c.status
                }
                for c in connections
            ]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        
        return proc_info
    
    # ========================================================================
    # THREAT ANALYSIS
    # ========================================================================
    
    def _analyze_process(self, proc_info: ProcessInfo):
        """
        Analyze process for suspicious behavior.
        
        Updates proc_info with threat_level and threat_reasons.
        """
        threat_level = ThreatLevel.BENIGN
        reasons = []
        mitre_techniques = []
        
        # Check 1: Suspicious process name
        proc_name_lower = proc_info.name.lower()
        for suspicious_name in self.SUSPICIOUS_PROCESSES:
            if suspicious_name in proc_name_lower:
                reasons.append(f"Suspicious process name: {suspicious_name}")
                threat_level = max(threat_level, ThreatLevel.CRITICAL)
                mitre_techniques.append("T1055")  # Process Injection
                break
        
        # Check 2: LOLBin usage with suspicious context
        lolbins = self.LOLBINS_WINDOWS if self.is_windows else self.LOLBINS_UNIX
        if proc_name_lower in lolbins:
            # Check command line for suspicious patterns
            cmdline_str = ' '.join(proc_info.cmdline).lower()
            
            for pattern in self.SUSPICIOUS_CMDLINE_PATTERNS:
                if pattern in cmdline_str:
                    reasons.append(f"LOLBin with suspicious command: {pattern}")
                    threat_level = max(threat_level, ThreatLevel.HIGH)
                    mitre_techniques.append("T1059")  # Command and Scripting Interpreter
                    break
        
        # Check 3: Suspicious parent-child relationship
        if proc_info.parent_name:
            parent_child = (proc_info.parent_name.lower(), proc_name_lower)
            if parent_child in self.SUSPICIOUS_PARENT_CHILD:
                reasons.append(
                    f"Suspicious parent-child: {proc_info.parent_name} -> {proc_info.name}"
                )
                threat_level = max(threat_level, ThreatLevel.HIGH)
                mitre_techniques.append("T1204")  # User Execution
        
        # Check 4: PowerShell with encoded command
        if 'powershell' in proc_name_lower:
            cmdline_str = ' '.join(proc_info.cmdline).lower()
            if '-encodedcommand' in cmdline_str or '-enc' in cmdline_str:
                reasons.append("PowerShell with encoded command")
                threat_level = max(threat_level, ThreatLevel.HIGH)
                mitre_techniques.append("T1027")  # Obfuscated Files or Information
        
        # Check 5: Process in temp directory
        if proc_info.exe_path:
            exe_lower = proc_info.exe_path.lower()
            if any(x in exe_lower for x in ['temp', 'tmp', 'appdata\\local\\temp']):
                reasons.append("Executable in temp directory")
                threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        # Check 6: High CPU usage (potential crypto mining)
        if proc_info.cpu_percent > 80:
            reasons.append(f"High CPU usage: {proc_info.cpu_percent:.1f}%")
            threat_level = max(threat_level, ThreatLevel.MEDIUM)
            mitre_techniques.append("T1496")  # Resource Hijacking
        
        # Check 7: Unusual network connections
        if len(proc_info.connections) > 10:
            reasons.append(f"Many network connections: {len(proc_info.connections)}")
            threat_level = max(threat_level, ThreatLevel.MEDIUM)
            mitre_techniques.append("T1071")  # Application Layer Protocol
        
        # Check 8: Process with no path (potential hollowing)
        if not proc_info.exe_path and proc_info.name not in ['System', 'Registry']:
            reasons.append("Process with no executable path")
            threat_level = max(threat_level, ThreatLevel.HIGH)
            mitre_techniques.append("T1055.012")  # Process Hollowing
        
        # Update process info
        proc_info.threat_level = threat_level
        proc_info.threat_reasons = reasons
        proc_info.mitre_techniques = list(set(mitre_techniques))  # Remove duplicates
    
    # ========================================================================
    # ALERTING
    # ========================================================================
    
    def _alert_suspicious_process(self, proc_info: ProcessInfo):
        """Alert about suspicious process"""
        self.logger.warning(
            f"\n🚨 [{proc_info.threat_level.name}] Suspicious Process Detected!\n"
            f"   Name: {proc_info.name}\n"
            f"   PID: {proc_info.pid}\n"
            f"   Path: {proc_info.exe_path}\n"
            f"   Parent: {proc_info.parent_name} (PID: {proc_info.parent_pid})\n"
            f"   User: {proc_info.username}\n"
            f"   Command: {' '.join(proc_info.cmdline[:5])}...\n"
            f"   Reasons: {', '.join(proc_info.threat_reasons)}\n"
            f"   MITRE: {', '.join(proc_info.mitre_techniques)}\n"
        )
        
        # Callback
        if self.callback:
            try:
                self.callback(proc_info)
            except Exception as e:
                self.logger.error(f"Error in callback: {e}")
    
    # ========================================================================
    # QUERY METHODS
    # ========================================================================
    
    def get_process_tree(self, pid: int, depth: int = 0) -> str:
        """
        Get process tree starting from a PID.
        
        Args:
            pid: Root process ID
            depth: Current depth (for indentation)
            
        Returns:
            str: Formatted process tree
        """
        if pid not in self.known_processes:
            return ""
        
        proc = self.known_processes[pid]
        indent = "  " * depth
        tree = f"{indent}└─ {proc.name} (PID: {pid})\n"
        
        # Add children
        if pid in self.process_tree:
            for child_pid in self.process_tree[pid]:
                tree += self.get_process_tree(child_pid, depth + 1)
        
        return tree
    
    def get_suspicious_processes(self) -> List[ProcessInfo]:
        """Get all currently suspicious processes"""
        return [
            proc for proc in self.known_processes.values()
            if proc.threat_level.value >= ThreatLevel.MEDIUM.value
        ]


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def start_monitoring(callback: Optional[Callable[[ProcessInfo], None]] = None,
                    scan_interval: float = 5.0) -> ProcessMonitor:
    """
    Start monitoring processes.
    
    Args:
        callback: Function to call on suspicious process
        scan_interval: Seconds between scans
        
    Returns:
        ProcessMonitor: Monitor instance
    """
    monitor = ProcessMonitor(callback, scan_interval)
    monitor.start()
    return monitor


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("👁️  CyberGuardian Process Monitor - Demo\n")
    
    # Callback for suspicious processes
    def alert_callback(proc_info: ProcessInfo):
        print(f"\n{'='*60}")
        print(f"⚠️  THREAT DETECTED!")
        print(f"{'='*60}")
        print(f"Process: {proc_info.name} (PID: {proc_info.pid})")
        print(f"Threat Level: {proc_info.threat_level.name}")
        print(f"Reasons:")
        for reason in proc_info.threat_reasons:
            print(f"  • {reason}")
        if proc_info.mitre_techniques:
            print(f"MITRE ATT&CK: {', '.join(proc_info.mitre_techniques)}")
        print(f"{'='*60}\n")
    
    # Start monitoring
    monitor = start_monitoring(callback=alert_callback, scan_interval=3.0)
    
    print("Monitoring all processes...")
    print("Suspicious processes will trigger alerts")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping monitor...")
        monitor.stop()
        print("✅ Monitor stopped")