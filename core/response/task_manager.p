"""
Task Manager - Windows Task Scheduler Malware Detection & Removal
Scans scheduled tasks for suspicious entries and provides removal with backup
"""

import json
import hashlib
import os
import platform
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Platform-specific imports
if platform.system() == "Windows":
    try:
        import win32com.client
    except ImportError:
        win32com = None
else:
    win32com = None

# Suspicious task indicators
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
    "downloader",
    
    # Script extensions
    ".bat",
    ".vbs",
    ".ps1",
    ".js",
    ".hta",
    
    # Suspicious behaviors
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bitsadmin.exe",
    "certutil.exe",
]

# Known legitimate task names (whitelist)
WHITELIST = [
    "microsoft",
    "windows",
    "adobe",
    "google",
    "defender",
    "security",
    "update",
    "backup",
    # Add more legitimate task prefixes
]

# Suspicious triggers
SUSPICIOUS_TRIGGERS = [
    "TASK_TRIGGER_LOGON",  # Run at logon
    "TASK_TRIGGER_BOOT",   # Run at boot
    "TASK_TRIGGER_DAILY",  # Daily execution
]


class TaskManager:
    """Windows Task Scheduler manager for malware detection and removal"""
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows" and win32com is not None
        self.backup_dir = "task_backups"
        self._ensure_backup_dir()
    
    def _ensure_backup_dir(self):
        """Create backup directory if it doesn't exist"""
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def scan_tasks(self) -> List[Dict]:
        """
        Scan all Windows scheduled tasks for suspicious entries
        
        Returns:
            List of suspicious tasks with details
        """
        if not self.is_windows:
            return []
        
        suspicious_tasks = []
        
        try:
            # Connect to Task Scheduler
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            
            # Get root task folder
            root_folder = scheduler.GetFolder("\\")
            
            # Recursively scan all tasks
            tasks = self._get_tasks_recursive(root_folder)
            
            for task_info in tasks:
                if self._is_suspicious(task_info):
                    suspicious_entry = {
                        "id": hashlib.md5(task_info["name"].encode()).hexdigest(),
                        "task_name": task_info["name"],
                        "path": task_info["path"],
                        "status": task_info["status"],
                        "enabled": task_info["enabled"],
                        "actions": task_info["actions"],
                        "triggers": task_info["triggers"],
                        "last_run": task_info["last_run"],
                        "next_run": task_info["next_run"],
                        "author": task_info.get("author", "Unknown"),
                        "risk_score": self._calculate_risk_score(task_info),
                        "indicators": self._get_indicators(task_info),
                        "scanned_at": datetime.utcnow().isoformat(),
                    }
                    suspicious_tasks.append(suspicious_entry)
        
        except Exception as e:
            print(f"Error scanning tasks: {str(e)}")
        
        return suspicious_tasks
    
    def _get_tasks_recursive(self, folder) -> List[Dict]:
        """
        Recursively get all tasks from a folder and its subfolders
        
        Args:
            folder: Task folder object
            
        Returns:
            List of task information dictionaries
        """
        tasks = []
        
        try:
            # Get tasks in current folder
            task_collection = folder.GetTasks(0)
            
            for task in task_collection:
                try:
                    task_info = self._extract_task_info(task)
                    if task_info:
                        tasks.append(task_info)
                except Exception as e:
                    print(f"Error processing task: {str(e)}")
                    continue
            
            # Recursively process subfolders
            subfolder_collection = folder.GetFolders(0)
            for subfolder in subfolder_collection:
                try:
                    tasks.extend(self._get_tasks_recursive(subfolder))
                except Exception as e:
                    print(f"Error processing subfolder: {str(e)}")
                    continue
        
        except Exception as e:
            print(f"Error getting tasks from folder: {str(e)}")
        
        return tasks
    
    def _extract_task_info(self, task) -> Optional[Dict]:
        """
        Extract information from a task object
        
        Args:
            task: Task object
            
        Returns:
            Dictionary with task details or None
        """
        try:
            definition = task.Definition
            
            # Extract actions
            actions = []
            for action in definition.Actions:
                if action.Type == 0:  # TASK_ACTION_EXEC
                    actions.append({
                        "type": "exec",
                        "path": action.Path,
                        "arguments": getattr(action, "Arguments", ""),
                        "working_directory": getattr(action, "WorkingDirectory", ""),
                    })
            
            # Extract triggers
            triggers = []
            for trigger in definition.Triggers:
                trigger_info = {
                    "type": self._get_trigger_type_name(trigger.Type),
                    "enabled": trigger.Enabled,
                }
                triggers.append(trigger_info)
            
            # Get last/next run time
            last_run = "Never"
            next_run = "Not scheduled"
            try:
                last_run = str(task.LastRunTime) if task.LastRunTime else "Never"
                next_run = str(task.NextRunTime) if task.NextRunTime else "Not scheduled"
            except:
                pass
            
            return {
                "name": task.Name,
                "path": task.Path,
                "status": self._get_task_state_name(task.State),
                "enabled": definition.Settings.Enabled,
                "actions": actions,
                "triggers": triggers,
                "last_run": last_run,
                "next_run": next_run,
                "author": getattr(definition.RegistrationInfo, "Author", "Unknown"),
            }
        
        except Exception as e:
            print(f"Error extracting task info: {str(e)}")
            return None
    
    def _is_suspicious(self, task_info: Dict) -> bool:
        """
        Check if a task is suspicious
        
        Args:
            task_info: Task information dictionary
            
        Returns:
            True if suspicious, False otherwise
        """
        task_name = task_info.get("name", "").lower()
        
        # Check whitelist first
        for safe_prefix in WHITELIST:
            if safe_prefix in task_name:
                return False
        
        # Check actions for suspicious patterns
        for action in task_info.get("actions", []):
            action_path = action.get("path", "").lower()
            action_args = action.get("arguments", "").lower()
            
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern.lower() in action_path or pattern.lower() in action_args:
                    return True
            
            # Check if executable exists
            if action_path and not os.path.exists(action_path):
                return True
        
        # Check for suspicious triggers
        for trigger in task_info.get("triggers", []):
            if trigger.get("type") in SUSPICIOUS_TRIGGERS and trigger.get("enabled"):
                # Additional checks for auto-start triggers
                for action in task_info.get("actions", []):
                    action_path = action.get("path", "").lower()
                    if any(pattern in action_path for pattern in SUSPICIOUS_PATTERNS):
                        return True
        
        return False
    
    def _calculate_risk_score(self, task_info: Dict) -> int:
        """
        Calculate risk score (0-100) based on suspicious indicators
        
        Args:
            task_info: Task information
            
        Returns:
            Risk score from 0-100
        """
        score = 0
        
        # Check actions
        for action in task_info.get("actions", []):
            action_path = action.get("path", "").lower()
            action_args = action.get("arguments", "").lower()
            
            # High-risk patterns
            high_risk = ["temp", "public", "miner", "crypto", "keylog"]
            for pattern in high_risk:
                if pattern in action_path or pattern in action_args:
                    score += 30
            
            # Medium-risk patterns
            medium_risk = ["cmd.exe", "powershell.exe", "wscript.exe", ".bat", ".vbs", ".ps1"]
            for pattern in medium_risk:
                if pattern in action_path or pattern in action_args:
                    score += 20
            
            # Executable doesn't exist
            if action_path and not os.path.exists(action_path):
                score += 25
        
        # Check triggers
        for trigger in task_info.get("triggers", []):
            if trigger.get("type") in ["TASK_TRIGGER_LOGON", "TASK_TRIGGER_BOOT"]:
                score += 15
            elif trigger.get("type") == "TASK_TRIGGER_DAILY":
                score += 10
        
        # Enabled task is more dangerous
        if task_info.get("enabled"):
            score += 10
        
        return min(score, 100)
    
    def _get_indicators(self, task_info: Dict) -> List[str]:
        """
        Get list of suspicious indicators for a task
        
        Args:
            task_info: Task information
            
        Returns:
            List of indicator descriptions
        """
        indicators = []
        
        # Check actions
        for action in task_info.get("actions", []):
            action_path = action.get("path", "").lower()
            action_args = action.get("arguments", "").lower()
            
            if any(p in action_path for p in ["temp", "public"]):
                indicators.append("Located in temporary/public directory")
            
            if any(p in action_path for p in ["cmd.exe", "powershell.exe", "wscript.exe"]):
                indicators.append("Uses scripting/command tool")
            
            if any(ext in action_path or ext in action_args for ext in [".bat", ".vbs", ".ps1"]):
                indicators.append("Executes script file")
            
            if action_path and not os.path.exists(action_path):
                indicators.append("Executable file not found")
            
            if any(name in action_path for name in ["miner", "crypto", "keylog"]):
                indicators.append("Suspicious task name")
        
        # Check triggers
        for trigger in task_info.get("triggers", []):
            trigger_type = trigger.get("type")
            if trigger_type == "TASK_TRIGGER_LOGON":
                indicators.append("Runs at user logon")
            elif trigger_type == "TASK_TRIGGER_BOOT":
                indicators.append("Runs at system boot")
            elif trigger_type == "TASK_TRIGGER_DAILY":
                indicators.append("Runs daily")
        
        if task_info.get("enabled"):
            indicators.append("Task is currently enabled")
        
        return list(set(indicators))  # Remove duplicates
    
    def _get_trigger_type_name(self, trigger_type: int) -> str:
        """Convert trigger type code to name"""
        trigger_types = {
            0: "TASK_TRIGGER_EVENT",
            1: "TASK_TRIGGER_TIME",
            2: "TASK_TRIGGER_DAILY",
            3: "TASK_TRIGGER_WEEKLY",
            4: "TASK_TRIGGER_MONTHLY",
            5: "TASK_TRIGGER_MONTHLYDOW",
            6: "TASK_TRIGGER_IDLE",
            7: "TASK_TRIGGER_REGISTRATION",
            8: "TASK_TRIGGER_BOOT",
            9: "TASK_TRIGGER_LOGON",
            11: "TASK_TRIGGER_SESSION_STATE_CHANGE",
        }
        return trigger_types.get(trigger_type, f"UNKNOWN_{trigger_type}")
    
    def _get_task_state_name(self, state: int) -> str:
        """Convert task state code to name"""
        states = {
            0: "Unknown",
            1: "Disabled",
            2: "Queued",
            3: "Ready",
            4: "Running",
        }
        return states.get(state, "Unknown")
    
    def backup_task(self, task_path: str) -> str:
        """
        Backup a task configuration before removal
        
        Args:
            task_path: Full path to the task
            
        Returns:
            Path to backup file
        """
        if not self.is_windows:
            return ""
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_id = hashlib.md5(task_path.encode()).hexdigest()[:8]
        backup_file = os.path.join(self.backup_dir, f"task_backup_{timestamp}_{backup_id}.json")
        
        try:
            # Connect to Task Scheduler
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            
            # Get task
            task = scheduler.GetTask(task_path)
            definition = task.Definition
            
            # Extract task XML
            task_xml = definition.XmlText
            
            # Create backup
            backup_data = {
                "task_path": task_path,
                "task_name": task.Name,
                "task_xml": task_xml,
                "author": getattr(definition.RegistrationInfo, "Author", "Unknown"),
                "backed_up_at": datetime.utcnow().isoformat(),
            }
            
            with open(backup_file, "w", encoding="utf-8") as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            return backup_file
        
        except Exception as e:
            print(f"Error backing up task: {str(e)}")
            return ""
    
    def delete_task(self, task_path: str) -> Tuple[bool, str]:
        """
        Delete a scheduled task (with automatic backup)
        
        Args:
            task_path: Full path to the task
            
        Returns:
            Tuple of (success, message/backup_file)
        """
        if not self.is_windows:
            return False, "Not a Windows system"
        
        # Backup first
        backup_file = self.backup_task(task_path)
        if not backup_file:
            return False, "Failed to create backup"
        
        try:
            # Connect to Task Scheduler
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            
            # Get folder and task name
            folder_path = "\\".join(task_path.split("\\")[:-1]) or "\\"
            task_name = task_path.split("\\")[-1]
            
            # Get folder
            folder = scheduler.GetFolder(folder_path)
            
            # Delete task
            folder.DeleteTask(task_name, 0)
            
            return True, backup_file
        
        except Exception as e:
            return False, f"Error deleting task: {str(e)}"
    
    def get_statistics(self, tasks: List[Dict]) -> Dict:
        """
        Get statistics from scan results
        
        Args:
            tasks: List of suspicious tasks
            
        Returns:
            Statistics dictionary
        """
        if not tasks:
            return {
                "total_suspicious": 0,
                "critical_risk": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "by_status": {},
                "enabled_count": 0,
                "disabled_count": 0,
            }
        
        stats = {
            "total_suspicious": len(tasks),
            "critical_risk": len([t for t in tasks if t["risk_score"] >= 80]),
            "high_risk": len([t for t in tasks if 60 <= t["risk_score"] < 80]),
            "medium_risk": len([t for t in tasks if 40 <= t["risk_score"] < 60]),
            "low_risk": len([t for t in tasks if t["risk_score"] < 40]),
            "by_status": {},
            "enabled_count": len([t for t in tasks if t["enabled"]]),
            "disabled_count": len([t for t in tasks if not t["enabled"]]),
        }
        
        # Count by status
        for task in tasks:
            status = task["status"]
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
        
        return stats


# Standalone functions for database integration
def scan_scheduled_tasks() -> List[Dict]:
    """Scan Windows scheduled tasks for suspicious entries"""
    manager = TaskManager()
    return manager.scan_tasks()


def delete_scheduled_task(task_path: str) -> Tuple[bool, str]:
    """Delete a scheduled task with backup"""
    manager = TaskManager()
    return manager.delete_task(task_path)


def get_task_statistics(tasks: List[Dict]) -> Dict:
    """Get statistics from task scan"""
    manager = TaskManager()
    return manager.get_statistics(tasks)