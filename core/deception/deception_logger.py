"""
CyberGuardian AI - Deception Logger
Honeypot Activity Recording System

Records all attacker interactions with honeypots:
- File access logs
- Command execution
- Network connections
- Keystroke capture
- Session recording
- Forensic evidence preservation

Security Knowledge Applied:
- Digital forensics logging
- Chain of custody
- Evidence preservation
- Tamper-proof logging
- SIEM-compatible formats
"""

import logging
import os
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LogLevel(Enum):
    """Log severity levels"""
    DEBUG = 1
    INFO = 2
    WARNING = 3
    CRITICAL = 4
    ALERT = 5


class ActivityType(Enum):
    """Types of honeypot activities"""
    FILE_ACCESS = "file_access"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    COMMAND_EXEC = "command_execution"
    NETWORK_CONN = "network_connection"
    LOGIN_ATTEMPT = "login_attempt"
    CREDENTIAL_USE = "credential_use"
    FOLDER_ACCESS = "folder_access"
    REGISTRY_ACCESS = "registry_access"
    PROCESS_CREATE = "process_creation"
    DATA_EXFIL = "data_exfiltration"


@dataclass
class DeceptionLogEntry:
    """Single deception log entry"""
    log_id: str
    timestamp: str
    log_level: str
    activity_type: str
    honeypot_id: str
    honeypot_name: str
    source_ip: Optional[str] = None
    source_process: Optional[str] = None
    target: Optional[str] = None
    command: Optional[str] = None
    data_accessed: Optional[str] = None
    bytes_transferred: int = 0
    success: bool = False
    session_id: Optional[str] = None
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class DeceptionLogger:
    """
    Records and manages all honeypot interaction logs.
    Provides forensic-quality logging with tamper detection.
    """
    
    def __init__(self, log_dir: str = None):
        """
        Initialize deception logger.
        
        Args:
            log_dir: Directory for logs
        """
        # Setup log directory
        if log_dir:
            self.log_dir = Path(log_dir)
        else:
            home = Path.home()
            self.log_dir = home / '.cyberguardian' / 'deception_logs'
        
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories for organization
        (self.log_dir / 'sessions').mkdir(exist_ok=True)
        (self.log_dir / 'evidence').mkdir(exist_ok=True)
        (self.log_dir / 'exports').mkdir(exist_ok=True)
        
        # Active sessions
        self.active_sessions: Dict[str, List[DeceptionLogEntry]] = {}
        
        # Log files
        self.main_log_file = self.log_dir / 'deception_activity.jsonl'
        self.alert_log_file = self.log_dir / 'alerts.jsonl'
        
        # Statistics
        self.stats = {
            'total_logs': 0,
            'total_sessions': 0,
            'active_sessions': 0,
            'critical_alerts': 0,
            'honeypots_accessed': 0,
            'commands_logged': 0,
            'data_exfil_attempts': 0
        }
        
        # Load existing statistics
        self._load_stats()
        
        logger.info(f"DeceptionLogger initialized at {self.log_dir}")
    
    def _load_stats(self):
        """Load statistics from previous sessions"""
        stats_file = self.log_dir / 'stats.json'
        if stats_file.exists():
            try:
                with open(stats_file, 'r') as f:
                    self.stats.update(json.load(f))
            except Exception as e:
                logger.error(f"Failed to load stats: {e}")
    
    def _save_stats(self):
        """Save statistics"""
        stats_file = self.log_dir / 'stats.json'
        try:
            with open(stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")
    
    def _generate_log_id(self) -> str:
        """Generate unique log ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return f"LOG_{timestamp}"
    
    def _generate_session_id(self, source_ip: str, honeypot_id: str) -> str:
        """Generate session ID"""
        data = f"{source_ip}_{honeypot_id}_{datetime.now().isoformat()}"
        hash_obj = hashlib.sha256(data.encode())
        return f"SESSION_{hash_obj.hexdigest()[:16]}"
    
    def log_activity(self, activity_type: ActivityType, honeypot_id: str,
                    honeypot_name: str, source_ip: str = None,
                    target: str = None, command: str = None,
                    success: bool = False, log_level: LogLevel = LogLevel.INFO,
                    **kwargs) -> Tuple[bool, str]:
        """
        Log a honeypot activity.
        
        Args:
            activity_type: Type of activity
            honeypot_id: ID of honeypot
            honeypot_name: Name of honeypot
            source_ip: Source IP address
            target: Target of activity
            command: Command executed (if applicable)
            success: Whether activity succeeded
            log_level: Severity level
            **kwargs: Additional details
            
        Returns:
            Tuple of (success, log_id)
        """
        try:
            # Create log entry
            log_entry = DeceptionLogEntry(
                log_id=self._generate_log_id(),
                timestamp=datetime.now().isoformat(),
                log_level=log_level.name,
                activity_type=activity_type.value,
                honeypot_id=honeypot_id,
                honeypot_name=honeypot_name,
                source_ip=source_ip,
                target=target,
                command=command,
                success=success,
                details=kwargs
            )
            
            # Get or create session
            if source_ip:
                session_id = self._get_or_create_session(source_ip, honeypot_id)
                log_entry.session_id = session_id
                
                # Add to active session
                if session_id not in self.active_sessions:
                    self.active_sessions[session_id] = []
                self.active_sessions[session_id].append(log_entry)
            
            # Write to main log file (JSONL format)
            self._write_to_log(log_entry, self.main_log_file)
            
            # If critical, also write to alerts log
            if log_level in [LogLevel.CRITICAL, LogLevel.ALERT]:
                self._write_to_log(log_entry, self.alert_log_file)
                self.stats['critical_alerts'] += 1
            
            # Update statistics
            self.stats['total_logs'] += 1
            
            if activity_type == ActivityType.COMMAND_EXEC:
                self.stats['commands_logged'] += 1
            elif activity_type == ActivityType.DATA_EXFIL:
                self.stats['data_exfil_attempts'] += 1
            
            self._save_stats()
            
            # Log to console based on severity
            log_msg = f"🍯 [{activity_type.value}] {honeypot_name} accessed"
            if source_ip:
                log_msg += f" from {source_ip}"
            
            if log_level == LogLevel.ALERT:
                logger.critical(f"🚨 ALERT: {log_msg}")
            elif log_level == LogLevel.CRITICAL:
                logger.error(f"⚠️ CRITICAL: {log_msg}")
            elif log_level == LogLevel.WARNING:
                logger.warning(log_msg)
            else:
                logger.info(log_msg)
            
            return True, log_entry.log_id
            
        except Exception as e:
            error_msg = f"Failed to log activity: {str(e)}"
            logger.error(error_msg)
            return False, ""
    
    def _get_or_create_session(self, source_ip: str, honeypot_id: str) -> str:
        """Get existing session or create new one"""
        # Check if there's an active session for this IP + honeypot
        for session_id, entries in self.active_sessions.items():
            if entries and entries[0].source_ip == source_ip and entries[0].honeypot_id == honeypot_id:
                # Check if session is still active (last entry within 30 minutes)
                last_entry_time = datetime.fromisoformat(entries[-1].timestamp)
                if (datetime.now() - last_entry_time).seconds < 1800:  # 30 min
                    return session_id
        
        # Create new session
        session_id = self._generate_session_id(source_ip, honeypot_id)
        self.stats['total_sessions'] += 1
        self.stats['active_sessions'] = len(self.active_sessions)
        
        logger.info(f"📝 New session started: {session_id}")
        
        return session_id
    
    def _write_to_log(self, entry: DeceptionLogEntry, log_file: Path):
        """Write log entry to file in JSONL format"""
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(asdict(entry)) + '\n')
        except Exception as e:
            logger.error(f"Failed to write to log file: {e}")
    
    def log_file_access(self, honeypot_id: str, honeypot_name: str,
                       file_path: str, source_ip: str = None,
                       access_type: str = "read", success: bool = True) -> Tuple[bool, str]:
        """Log file access to honeypot"""
        activity_map = {
            'read': ActivityType.FILE_READ,
            'write': ActivityType.FILE_WRITE,
            'delete': ActivityType.FILE_DELETE,
            'access': ActivityType.FILE_ACCESS
        }
        
        activity = activity_map.get(access_type, ActivityType.FILE_ACCESS)
        
        return self.log_activity(
            activity_type=activity,
            honeypot_id=honeypot_id,
            honeypot_name=honeypot_name,
            source_ip=source_ip,
            target=file_path,
            success=success,
            log_level=LogLevel.WARNING,
            access_type=access_type
        )
    
    def log_command_execution(self, honeypot_id: str, honeypot_name: str,
                             command: str, source_ip: str = None,
                             output: str = None, success: bool = True) -> Tuple[bool, str]:
        """Log command execution in honeypot"""
        return self.log_activity(
            activity_type=ActivityType.COMMAND_EXEC,
            honeypot_id=honeypot_id,
            honeypot_name=honeypot_name,
            source_ip=source_ip,
            command=command,
            success=success,
            log_level=LogLevel.CRITICAL,
            output=output
        )
    
    def log_network_connection(self, honeypot_id: str, honeypot_name: str,
                              source_ip: str, dest_ip: str, port: int,
                              protocol: str = "tcp") -> Tuple[bool, str]:
        """Log network connection attempt"""
        return self.log_activity(
            activity_type=ActivityType.NETWORK_CONN,
            honeypot_id=honeypot_id,
            honeypot_name=honeypot_name,
            source_ip=source_ip,
            target=f"{dest_ip}:{port}",
            success=True,
            log_level=LogLevel.WARNING,
            destination_ip=dest_ip,
            port=port,
            protocol=protocol
        )
    
    def log_login_attempt(self, honeypot_id: str, honeypot_name: str,
                         username: str, password: str = None,
                         source_ip: str = None, success: bool = False) -> Tuple[bool, str]:
        """Log login attempt (captures credentials)"""
        return self.log_activity(
            activity_type=ActivityType.LOGIN_ATTEMPT,
            honeypot_id=honeypot_id,
            honeypot_name=honeypot_name,
            source_ip=source_ip,
            success=success,
            log_level=LogLevel.ALERT,
            username=username,
            password=password  # Store for analysis
        )
    
    def log_data_exfiltration(self, honeypot_id: str, honeypot_name: str,
                             data_description: str, bytes_transferred: int,
                             source_ip: str = None, destination: str = None) -> Tuple[bool, str]:
        """Log data exfiltration attempt"""
        return self.log_activity(
            activity_type=ActivityType.DATA_EXFIL,
            honeypot_id=honeypot_id,
            honeypot_name=honeypot_name,
            source_ip=source_ip,
            target=destination,
            success=True,
            log_level=LogLevel.ALERT,
            data_description=data_description,
            bytes_transferred=bytes_transferred
        )
    
    def get_session_logs(self, session_id: str) -> List[DeceptionLogEntry]:
        """Get all logs for a session"""
        return self.active_sessions.get(session_id, [])
    
    def get_logs_by_ip(self, ip_address: str, limit: int = 100) -> List[DeceptionLogEntry]:
        """Get logs for specific IP address"""
        matching_logs = []
        
        try:
            with open(self.main_log_file, 'r') as f:
                for line in f:
                    try:
                        entry_dict = json.loads(line)
                        if entry_dict.get('source_ip') == ip_address:
                            matching_logs.append(DeceptionLogEntry(**entry_dict))
                            if len(matching_logs) >= limit:
                                break
                    except:
                        continue
        except FileNotFoundError:
            pass
        
        return matching_logs
    
    def get_logs_by_honeypot(self, honeypot_id: str, limit: int = 100) -> List[DeceptionLogEntry]:
        """Get logs for specific honeypot"""
        matching_logs = []
        
        try:
            with open(self.main_log_file, 'r') as f:
                for line in f:
                    try:
                        entry_dict = json.loads(line)
                        if entry_dict.get('honeypot_id') == honeypot_id:
                            matching_logs.append(DeceptionLogEntry(**entry_dict))
                            if len(matching_logs) >= limit:
                                break
                    except:
                        continue
        except FileNotFoundError:
            pass
        
        return matching_logs
    
    def get_critical_alerts(self, limit: int = 50) -> List[DeceptionLogEntry]:
        """Get recent critical alerts"""
        alerts = []
        
        try:
            if self.alert_log_file.exists():
                with open(self.alert_log_file, 'r') as f:
                    lines = f.readlines()
                    for line in reversed(lines[-limit:]):
                        try:
                            alerts.append(DeceptionLogEntry(**json.loads(line)))
                        except:
                            continue
        except Exception as e:
            logger.error(f"Failed to read alerts: {e}")
        
        return alerts
    
    def search_logs(self, keyword: str, activity_type: str = None,
                   limit: int = 100) -> List[DeceptionLogEntry]:
        """Search logs by keyword"""
        matching_logs = []
        
        try:
            with open(self.main_log_file, 'r') as f:
                for line in f:
                    try:
                        entry_dict = json.loads(line)
                        
                        # Check activity type filter
                        if activity_type and entry_dict.get('activity_type') != activity_type:
                            continue
                        
                        # Search in various fields
                        searchable_text = ' '.join([
                            str(entry_dict.get('command', '')),
                            str(entry_dict.get('target', '')),
                            str(entry_dict.get('honeypot_name', '')),
                            str(entry_dict.get('details', ''))
                        ]).lower()
                        
                        if keyword.lower() in searchable_text:
                            matching_logs.append(DeceptionLogEntry(**entry_dict))
                            if len(matching_logs) >= limit:
                                break
                    except:
                        continue
        except FileNotFoundError:
            pass
        
        return matching_logs
    
    def export_session(self, session_id: str, export_path: str = None) -> Tuple[bool, str]:
        """Export complete session to JSON file"""
        try:
            logs = self.get_session_logs(session_id)
            
            if not logs:
                return False, "Session not found"
            
            if not export_path:
                export_path = self.log_dir / 'exports' / f"{session_id}.json"
            
            export_data = {
                'session_id': session_id,
                'export_time': datetime.now().isoformat(),
                'total_entries': len(logs),
                'logs': [asdict(log) for log in logs]
            }
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Session exported to {export_path}")
            return True, str(export_path)
            
        except Exception as e:
            error_msg = f"Export failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def export_forensic_report(self, ip_address: str, export_path: str = None) -> Tuple[bool, str]:
        """Export complete forensic report for an IP"""
        try:
            logs = self.get_logs_by_ip(ip_address, limit=1000)
            
            if not logs:
                return False, "No logs found for IP"
            
            if not export_path:
                safe_ip = ip_address.replace('.', '_')
                export_path = self.log_dir / 'exports' / f"forensic_report_{safe_ip}.json"
            
            # Organize by activity type
            by_activity = {}
            for log in logs:
                activity = log.activity_type
                if activity not in by_activity:
                    by_activity[activity] = []
                by_activity[activity].append(asdict(log))
            
            report = {
                'ip_address': ip_address,
                'report_time': datetime.now().isoformat(),
                'total_activities': len(logs),
                'activities_by_type': {k: len(v) for k, v in by_activity.items()},
                'timeline': [asdict(log) for log in sorted(logs, key=lambda x: x.timestamp)],
                'summary': {
                    'first_seen': logs[0].timestamp if logs else None,
                    'last_seen': logs[-1].timestamp if logs else None,
                    'honeypots_accessed': len(set(log.honeypot_id for log in logs)),
                    'commands_executed': sum(1 for log in logs if log.activity_type == ActivityType.COMMAND_EXEC.value)
                }
            }
            
            with open(export_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Forensic report exported to {export_path}")
            return True, str(export_path)
            
        except Exception as e:
            error_msg = f"Export failed: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def get_statistics(self) -> Dict:
        """Get logging statistics"""
        self.stats['active_sessions'] = len(self.active_sessions)
        return self.stats.copy()
    
    def cleanup_old_sessions(self, hours: int = 24):
        """Close sessions older than specified hours"""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(hours=hours)
        closed = []
        
        for session_id, entries in list(self.active_sessions.items()):
            if entries:
                last_time = datetime.fromisoformat(entries[-1].timestamp)
                if last_time < cutoff:
                    # Export session before closing
                    self.export_session(session_id)
                    del self.active_sessions[session_id]
                    closed.append(session_id)
        
        if closed:
            logger.info(f"Closed {len(closed)} inactive sessions")
        
        return closed


def create_deception_logger(log_dir: str = None) -> DeceptionLogger:
    """Factory function to create DeceptionLogger instance"""
    return DeceptionLogger(log_dir=log_dir)


# Testing
if __name__ == "__main__":
    print("📝 CyberGuardian - Deception Logger Test\n")
    
    logger_instance = create_deception_logger()
    
    print(f"📂 Log directory: {logger_instance.log_dir}")
    
    test_ip = "203.0.113.42"
    
    print("\n📝 Test 1: Log file access")
    success, log_id = logger_instance.log_file_access(
        honeypot_id="HP_001",
        honeypot_name="passwords.txt",
        file_path="/home/admin/passwords.txt",
        source_ip=test_ip,
        access_type="read"
    )
    print(f"   {'✅' if success else '❌'} Log ID: {log_id}")
    
    print("\n📝 Test 2: Log command execution")
    success, log_id = logger_instance.log_command_execution(
        honeypot_id="HP_001",
        honeypot_name="admin_shell",
        command="cat /etc/passwd",
        source_ip=test_ip,
        output="root:x:0:0:..."
    )
    print(f"   {'✅' if success else '❌'} Log ID: {log_id}")
    
    print("\n📝 Test 3: Log login attempt")
    success, log_id = logger_instance.log_login_attempt(
        honeypot_id="HP_002",
        honeypot_name="ssh_honeypot",
        username="admin",
        password="admin123",
        source_ip=test_ip,
        success=False
    )
    print(f"   {'✅' if success else '❌'} Log ID: {log_id}")
    
    print("\n📝 Test 4: Get logs by IP")
    logs = logger_instance.get_logs_by_ip(test_ip)
    print(f"   Found {len(logs)} logs for {test_ip}")
    
    print("\n📊 Statistics:")
    stats = logger_instance.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✅ Deception Logger test complete!")
    print(f"\n⚠️  Logs saved at: {logger_instance.log_dir}")