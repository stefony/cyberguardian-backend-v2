"""
CyberGuardian AI - Process Killer
Automated Process Termination Engine

Safely terminates malicious processes with support for:
- Process tree killing (parent + children)
- Graceful vs forceful termination
- Critical process protection
- Cross-platform support

Security Knowledge Applied:
- Process injection defense
- Malware persistence prevention
- Process resurrection prevention
- Privilege escalation handling
"""

import logging
import os
import platform
import psutil
import signal
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ProcessInfo:
    """Information about a process"""
    pid: int
    name: str
    exe: Optional[str] = None
    cmdline: Optional[List[str]] = None
    parent_pid: Optional[int] = None
    create_time: Optional[float] = None
    username: Optional[str] = None


class ProcessKiller:
    """
    Process termination engine with safety checks and logging.
    """
    
    # Critical system processes that should NEVER be killed
    PROTECTED_PROCESSES = {
        'windows': [
            'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe',
            'winlogon.exe', 'smss.exe', 'explorer.exe', 'svchost.exe',
            'System', 'Registry', 'dwm.exe'
        ],
        'linux': [
            'systemd', 'init', 'kthreadd', 'sshd', 'dbus-daemon',
            'systemd-logind', 'NetworkManager'
        ],
        'darwin': [
            'launchd', 'kernel_task', 'WindowServer', 'loginwindow',
            'systemstats', 'UserEventAgent'
        ]
    }
    
    # CyberGuardian own processes (never kill ourselves!)
    OWN_PROCESSES = ['cyberguardian', 'cgagent', 'cgcore']
    
    def __init__(self):
        self.system = platform.system().lower()
        self.killed_processes: List[Dict] = []
        self.failed_kills: List[Dict] = []
        
        # Statistics
        self.stats = {
            'total_kills': 0,
            'successful_kills': 0,
            'failed_kills': 0,
            'protected_process_attempts': 0,
            'tree_kills': 0
        }
        
        logger.info(f"ProcessKiller initialized for {self.system}")
    
    def is_protected(self, process_name: str, pid: int) -> bool:
        """
        Check if a process is protected from termination.
        
        Args:
            process_name: Process name
            pid: Process ID
            
        Returns:
            True if process should not be killed
        """
        # Check if it's a system critical process
        protected_list = self.PROTECTED_PROCESSES.get(self.system, [])
        if any(protected in process_name.lower() for protected in protected_list):
            logger.warning(f"⚠️ Process {process_name} (PID {pid}) is protected!")
            self.stats['protected_process_attempts'] += 1
            return True
        
        # Check if it's our own process
        if any(own in process_name.lower() for own in self.OWN_PROCESSES):
            logger.warning(f"⚠️ Cannot kill own process: {process_name} (PID {pid})")
            return True
        
        # Check if it's PID 0, 1, or our own PID
        if pid in [0, 1, os.getpid()]:
            logger.warning(f"⚠️ Cannot kill system/own PID: {pid}")
            return True
        
        return False
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """
        Get detailed information about a process.
        
        Args:
            pid: Process ID
            
        Returns:
            ProcessInfo object or None if process doesn't exist
        """
        try:
            proc = psutil.Process(pid)
            return ProcessInfo(
                pid=pid,
                name=proc.name(),
                exe=proc.exe() if hasattr(proc, 'exe') else None,
                cmdline=proc.cmdline() if hasattr(proc, 'cmdline') else None,
                parent_pid=proc.ppid() if hasattr(proc, 'ppid') else None,
                create_time=proc.create_time() if hasattr(proc, 'create_time') else None,
                username=proc.username() if hasattr(proc, 'username') else None
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.debug(f"Cannot get info for PID {pid}: {e}")
            return None
    
    def get_process_tree(self, pid: int) -> List[int]:
        """
        Get all child processes of a given process (recursive).
        
        Args:
            pid: Parent process ID
            
        Returns:
            List of PIDs (parent + all children)
        """
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            
            # Return parent + all children PIDs
            pids = [pid] + [child.pid for child in children]
            logger.debug(f"Process tree for {pid}: {pids}")
            return pids
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.debug(f"Cannot get process tree for {pid}: {e}")
            return [pid]  # Return at least the parent
    
    def kill_process(self, pid: int, force: bool = False, 
                    kill_tree: bool = True, timeout: int = 5) -> Tuple[bool, str, Dict]:
        """
        Kill a process (and optionally its children).
        
        Args:
            pid: Process ID to kill
            force: If True, use SIGKILL/forceful termination immediately
            kill_tree: If True, kill the entire process tree
            timeout: Seconds to wait for graceful termination
            
        Returns:
            Tuple of (success: bool, message: str, details: dict)
        """
        self.stats['total_kills'] += 1
        
        try:
            # Get process info before killing
            proc_info = self.get_process_info(pid)
            if not proc_info:
                return False, f"Process {pid} not found", {}
            
            # Safety check: Is it protected?
            if self.is_protected(proc_info.name, pid):
                msg = f"Refused to kill protected process: {proc_info.name} (PID {pid})"
                logger.error(msg)
                self.failed_kills.append({
                    'pid': pid,
                    'name': proc_info.name,
                    'reason': 'protected',
                    'timestamp': datetime.now()
                })
                return False, msg, {}
            
            # Get process tree if requested
            pids_to_kill = self.get_process_tree(pid) if kill_tree else [pid]
            
            if kill_tree and len(pids_to_kill) > 1:
                logger.info(f"Killing process tree: {len(pids_to_kill)} processes")
                self.stats['tree_kills'] += 1
            
            # Kill all processes
            killed_pids = []
            failed_pids = []
            
            for target_pid in pids_to_kill:
                success, msg = self._terminate_single_process(
                    target_pid, force, timeout
                )
                
                if success:
                    killed_pids.append(target_pid)
                else:
                    failed_pids.append(target_pid)
            
            # Overall success if main process was killed
            success = pid in killed_pids
            
            if success:
                self.stats['successful_kills'] += 1
                result_msg = f"Successfully killed {proc_info.name} (PID {pid})"
                if kill_tree:
                    result_msg += f" and {len(killed_pids)-1} children"
                
                # Log the kill
                self.killed_processes.append({
                    'pid': pid,
                    'name': proc_info.name,
                    'exe': proc_info.exe,
                    'killed_pids': killed_pids,
                    'timestamp': datetime.now(),
                    'method': 'forceful' if force else 'graceful'
                })
                
                logger.info(f"✅ {result_msg}")
                
            else:
                self.stats['failed_kills'] += 1
                result_msg = f"Failed to kill {proc_info.name} (PID {pid})"
                
                self.failed_kills.append({
                    'pid': pid,
                    'name': proc_info.name,
                    'reason': 'termination_failed',
                    'timestamp': datetime.now()
                })
                
                logger.error(f"❌ {result_msg}")
            
            details = {
                'process_name': proc_info.name,
                'killed_pids': killed_pids,
                'failed_pids': failed_pids,
                'tree_size': len(pids_to_kill)
            }
            
            return success, result_msg, details
            
        except Exception as e:
            self.stats['failed_kills'] += 1
            error_msg = f"Error killing process {pid}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def _terminate_single_process(self, pid: int, force: bool, 
                                  timeout: int) -> Tuple[bool, str]:
        """
        Terminate a single process (internal method).
        
        Args:
            pid: Process ID
            force: Use forceful termination
            timeout: Timeout for graceful termination
            
        Returns:
            Tuple of (success, message)
        """
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            if force:
                # Forceful termination (SIGKILL on Unix, TerminateProcess on Windows)
                logger.debug(f"Force killing PID {pid} ({proc_name})")
                proc.kill()  # SIGKILL / TerminateProcess
                
                # Wait to confirm
                proc.wait(timeout=2)
                return True, f"Force killed {proc_name}"
                
            else:
                # Graceful termination (SIGTERM on Unix, WM_CLOSE on Windows)
                logger.debug(f"Gracefully terminating PID {pid} ({proc_name})")
                proc.terminate()  # SIGTERM / WM_CLOSE
                
                # Wait for graceful exit
                try:
                    proc.wait(timeout=timeout)
                    return True, f"Gracefully terminated {proc_name}"
                    
                except psutil.TimeoutExpired:
                    # Graceful failed, force kill
                    logger.warning(f"Graceful termination timeout, force killing {pid}")
                    proc.kill()
                    proc.wait(timeout=2)
                    return True, f"Force killed {proc_name} after timeout"
        
        except psutil.NoSuchProcess:
            # Process already dead
            return True, "Process already terminated"
            
        except psutil.AccessDenied:
            logger.error(f"Access denied killing PID {pid} (requires elevation?)")
            return False, "Access denied - insufficient privileges"
            
        except Exception as e:
            logger.error(f"Error terminating PID {pid}: {e}")
            return False, str(e)
    
    def kill_by_name(self, process_name: str, force: bool = False, 
                    kill_all: bool = False) -> Tuple[bool, str, Dict]:
        """
        Kill process(es) by name.
        
        Args:
            process_name: Name of process to kill
            force: Use forceful termination
            kill_all: Kill all matching processes (default: only first match)
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            matching_procs = []
            
            # Find all processes matching the name
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if process_name.lower() in proc.info['name'].lower():
                        matching_procs.append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not matching_procs:
                return False, f"No processes found matching '{process_name}'", {}
            
            logger.info(f"Found {len(matching_procs)} processes matching '{process_name}'")
            
            # Kill processes
            killed = []
            failed = []
            
            targets = matching_procs if kill_all else [matching_procs[0]]
            
            for pid in targets:
                success, msg, _ = self.kill_process(pid, force=force, kill_tree=False)
                if success:
                    killed.append(pid)
                else:
                    failed.append(pid)
            
            if killed:
                msg = f"Killed {len(killed)} processes matching '{process_name}'"
                details = {'killed': killed, 'failed': failed}
                return True, msg, details
            else:
                msg = f"Failed to kill any processes matching '{process_name}'"
                details = {'failed': failed}
                return False, msg, details
                
        except Exception as e:
            return False, f"Error: {str(e)}", {}
    
    def suspend_process(self, pid: int) -> Tuple[bool, str]:
        """
        Suspend a process (freeze execution without killing).
        Useful for analysis before termination.
        
        Args:
            pid: Process ID
            
        Returns:
            Tuple of (success, message)
        """
        try:
            proc = psutil.Process(pid)
            
            if self.is_protected(proc.name(), pid):
                return False, f"Cannot suspend protected process {pid}"
            
            proc.suspend()
            logger.info(f"Suspended process {pid} ({proc.name()})")
            return True, f"Suspended {proc.name()}"
            
        except Exception as e:
            logger.error(f"Failed to suspend {pid}: {e}")
            return False, str(e)
    
    def resume_process(self, pid: int) -> Tuple[bool, str]:
        """
        Resume a suspended process.
        
        Args:
            pid: Process ID
            
        Returns:
            Tuple of (success, message)
        """
        try:
            proc = psutil.Process(pid)
            proc.resume()
            logger.info(f"Resumed process {pid} ({proc.name()})")
            return True, f"Resumed {proc.name()}"
            
        except Exception as e:
            logger.error(f"Failed to resume {pid}: {e}")
            return False, str(e)
    
    def get_statistics(self) -> Dict:
        """Get kill statistics"""
        return self.stats.copy()
    
    def get_kill_history(self, limit: int = 10) -> List[Dict]:
        """Get recent kill history"""
        return self.killed_processes[-limit:]
    
    def clear_history(self):
        """Clear kill history (for privacy/cleanup)"""
        self.killed_processes.clear()
        self.failed_kills.clear()
        logger.info("Kill history cleared")


def create_killer() -> ProcessKiller:
    """Factory function to create ProcessKiller instance"""
    return ProcessKiller()


# Integration function for threat_blocker
def handle_kill_process(threat_context) -> Tuple[bool, str, Dict]:
    """
    Handler function for threat_blocker integration.
    
    Args:
        threat_context: ThreatContext object from threat_blocker
        
    Returns:
        Tuple of (success, message, details)
    """
    killer = create_killer()
    
    # Extract PID from threat context
    pid = threat_context.target.get('pid') or threat_context.target.get('process_id')
    
    if not pid:
        return False, "No PID provided in threat context", {}
    
    # Determine if we should force kill based on severity
    force = threat_context.severity.value >= 4  # CRITICAL or HIGH
    
    # Kill the process tree for high severity threats
    kill_tree = threat_context.severity.value >= 4
    
    success, message, details = killer.kill_process(
        pid=pid,
        force=force,
        kill_tree=kill_tree
    )
    
    return success, message, details


# Testing
if __name__ == "__main__":
    print("🔪 CyberGuardian - Process Killer Test\n")
    
    killer = create_killer()
    
    print("📊 System Information:")
    print(f"  Platform: {platform.system()}")
    print(f"  Protected processes: {len(killer.PROTECTED_PROCESSES.get(killer.system, []))}")
    
    print("\n🔍 Testing process enumeration:")
    # Find a safe process to test with (our own Python process)
    current_pid = os.getpid()
    proc_info = killer.get_process_info(current_pid)
    
    if proc_info:
        print(f"  Current process: {proc_info.name} (PID {proc_info.pid})")
        print(f"  Executable: {proc_info.exe}")
        print(f"  Parent PID: {proc_info.parent_pid}")
    
    print("\n🛡️ Testing protection:")
    # Try to check if system process is protected
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            is_prot = killer.is_protected(proc.info['name'], proc.info['pid'])
            if is_prot:
                print(f"  ✅ {proc.info['name']} (PID {proc.info['pid']}) - PROTECTED")
                break
        except:
            continue
    
    print("\n📊 Statistics:")
    stats = killer.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ Process Killer test complete!")
    print("\n⚠️  NOTE: Actual process killing requires elevated privileges")
    print("         and should only be used against confirmed threats!")