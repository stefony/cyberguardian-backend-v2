"""
CyberGuardian AI - Process Watchdog
Monitors main process health and provides auto-restart capabilities
"""

import os
import sys
import time
import psutil
import subprocess
import signal
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Watchdog configuration
MAX_RESTARTS = 5  # Maximum restarts within time window
RESTART_WINDOW = timedelta(minutes=10)  # Time window for restart counting
COOLDOWN_PERIOD = 30  # Seconds to wait before restart
HEALTH_CHECK_INTERVAL = 10  # Seconds between health checks
PROCESS_TIMEOUT = 300  # Maximum seconds without response before restart

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
MAIN_SCRIPT = BASE_DIR / "main.py"
WATCHDOG_LOG = BASE_DIR / "logs" / "watchdog.log"
RESTART_LOG = BASE_DIR / "logs" / "restarts.json"

# Ensure logs directory exists
(BASE_DIR / "logs").mkdir(exist_ok=True)


class ProcessWatchdog:
    """
    Monitors and protects the main CyberGuardian process
    """
    
    def __init__(self, process_name: str = "main.py", python_executable: Optional[str] = None):
        self.process_name = process_name
        self.python_executable = python_executable or sys.executable
        self.monitored_process: Optional[psutil.Process] = None
        self.restart_history: list = []
        self.is_running = False
        self.should_stop = False
        
        # Load restart history
        self._load_restart_history()
    
    def _load_restart_history(self):
        """Load restart history from file"""
        try:
            if RESTART_LOG.exists():
                with open(RESTART_LOG, "r") as f:
                    data = json.load(f)
                    self.restart_history = [
                        {
                            "timestamp": datetime.fromisoformat(entry["timestamp"]),
                            "reason": entry["reason"]
                        }
                        for entry in data
                    ]
                logger.info(f"📋 Loaded {len(self.restart_history)} restart records")
        except Exception as e:
            logger.error(f"❌ Error loading restart history: {e}")
            self.restart_history = []
    
    def _save_restart_history(self):
        """Save restart history to file"""
        try:
            data = [
                {
                    "timestamp": entry["timestamp"].isoformat(),
                    "reason": entry["reason"]
                }
                for entry in self.restart_history
            ]
            with open(RESTART_LOG, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"❌ Error saving restart history: {e}")
    
    def _log_restart(self, reason: str):
        """
        Log a restart event
        
        Args:
            reason: Reason for restart
        """
        entry = {
            "timestamp": datetime.now(),
            "reason": reason
        }
        self.restart_history.append(entry)
        self._save_restart_history()
        
        # Keep only recent history (within window)
        cutoff = datetime.now() - RESTART_WINDOW
        self.restart_history = [
            e for e in self.restart_history
            if e["timestamp"] > cutoff
        ]
        
        logger.info(f"📝 Restart logged: {reason}")
    
    def _check_restart_limit(self) -> bool:
        """
        Check if restart limit has been exceeded
        
        Returns:
            True if restart is allowed, False otherwise
        """
        recent_restarts = len(self.restart_history)
        
        if recent_restarts >= MAX_RESTARTS:
            logger.error(f"🚨 RESTART LIMIT EXCEEDED: {recent_restarts} restarts in last {RESTART_WINDOW}")
            logger.error("⚠️ Possible crash loop detected - stopping watchdog")
            return False
        
        logger.info(f"✅ Restart allowed ({recent_restarts}/{MAX_RESTARTS} in window)")
        return True
    
    def find_process(self) -> Optional[psutil.Process]:
        """
        Find the main CyberGuardian process
        
        Returns:
            Process object if found, None otherwise
        """
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info.get('cmdline', [])
                    if cmdline and self.process_name in ' '.join(cmdline):
                        logger.info(f"✅ Found process: PID {proc.pid}")
                        return proc
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            logger.warning(f"⚠️ Process not found: {self.process_name}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error finding process: {e}")
            return None
    
    def start_process(self) -> Optional[psutil.Process]:
        """
        Start the main CyberGuardian process
        
        Returns:
            Process object if started successfully
        """
        try:
            logger.info(f"🚀 Starting process: {MAIN_SCRIPT}")
            
            # Start process
            process = subprocess.Popen(
                [self.python_executable, str(MAIN_SCRIPT)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(BASE_DIR)
            )
            
            # Wait a moment to ensure it started
            time.sleep(2)
            
            # Verify it's running
            if process.poll() is None:
                proc = psutil.Process(process.pid)
                logger.info(f"✅ Process started successfully: PID {process.pid}")
                return proc
            else:
                logger.error("❌ Process failed to start")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error starting process: {e}")
            return None
    
    def check_process_health(self, process: psutil.Process) -> bool:
        """
        Check if process is healthy
        
        Args:
            process: Process to check
            
        Returns:
            True if healthy, False otherwise
        """
        try:
            if not process.is_running():
                logger.warning("⚠️ Process is not running")
                return False
            
            # Check CPU usage (detect hung process)
            cpu_percent = process.cpu_percent(interval=1)
            if cpu_percent > 95:
                logger.warning(f"⚠️ High CPU usage: {cpu_percent}%")
            
            # Check memory usage
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            if memory_mb > 2000:  # More than 2GB
                logger.warning(f"⚠️ High memory usage: {memory_mb:.2f} MB")
            
            # Check if process is responding (basic check)
            status = process.status()
            if status == psutil.STATUS_ZOMBIE:
                logger.error("❌ Process is zombie")
                return False
            
            logger.debug(f"✅ Process healthy: CPU {cpu_percent}%, Memory {memory_mb:.2f} MB")
            return True
            
        except psutil.NoSuchProcess:
            logger.error("❌ Process no longer exists")
            return False
        except Exception as e:
            logger.error(f"❌ Error checking process health: {e}")
            return False
    
    def restart_process(self, reason: str = "Health check failed") -> Optional[psutil.Process]:
        """
        Restart the main process
        
        Args:
            reason: Reason for restart
            
        Returns:
            New process object if successful
        """
        # Check restart limit
        if not self._check_restart_limit():
            logger.error("🛑 Restart aborted due to limit")
            self.should_stop = True
            return None
        
        logger.warning(f"🔄 Restarting process: {reason}")
        
        # Stop existing process
        if self.monitored_process:
            try:
                logger.info("⏸️ Stopping existing process...")
                self.monitored_process.terminate()
                self.monitored_process.wait(timeout=10)
            except Exception as e:
                logger.error(f"❌ Error stopping process: {e}")
                try:
                    self.monitored_process.kill()
                except:
                    pass
        
        # Cooldown period
        logger.info(f"⏳ Cooldown period: {COOLDOWN_PERIOD} seconds")
        time.sleep(COOLDOWN_PERIOD)
        
        # Log restart
        self._log_restart(reason)
        
        # Start new process
        new_process = self.start_process()
        
        if new_process:
            logger.info("✅ Process restarted successfully")
            return new_process
        else:
            logger.error("❌ Failed to restart process")
            return None
    
    def monitor(self):
        """
        Main monitoring loop
        """
        self.is_running = True
        logger.info("👁️ Watchdog monitoring started")
        
        # Find or start process
        self.monitored_process = self.find_process()
        
        if not self.monitored_process:
            logger.info("Process not found, starting...")
            self.monitored_process = self.start_process()
        
        if not self.monitored_process:
            logger.error("❌ Failed to start initial process")
            return
        
        # Monitoring loop
        while not self.should_stop:
            try:
                # Health check
                if not self.check_process_health(self.monitored_process):
                    logger.warning("⚠️ Health check failed - attempting restart")
                    self.monitored_process = self.restart_process("Health check failed")
                    
                    if not self.monitored_process:
                        logger.error("❌ Restart failed - stopping watchdog")
                        break
                
                # Sleep until next check
                time.sleep(HEALTH_CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("⏹️ Watchdog stopped by user")
                self.should_stop = True
            except Exception as e:
                logger.error(f"❌ Error in monitoring loop: {e}")
                time.sleep(HEALTH_CHECK_INTERVAL)
        
        self.is_running = False
        logger.info("👋 Watchdog monitoring stopped")
    
    def stop(self):
        """Stop the watchdog"""
        logger.info("🛑 Stopping watchdog...")
        self.should_stop = True
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get watchdog status
        
        Returns:
            Status dictionary
        """
        status = {
            "is_running": self.is_running,
            "monitored_process": None,
            "restart_count": len(self.restart_history),
            "recent_restarts": [
                {
                    "timestamp": e["timestamp"].isoformat(),
                    "reason": e["reason"]
                }
                for e in self.restart_history[-10:]  # Last 10 restarts
            ]
        }
        
        if self.monitored_process:
            try:
                status["monitored_process"] = {
                    "pid": self.monitored_process.pid,
                    "status": self.monitored_process.status(),
                    "cpu_percent": self.monitored_process.cpu_percent(interval=0.1),
                    "memory_mb": self.monitored_process.memory_info().rss / 1024 / 1024,
                    "create_time": datetime.fromtimestamp(self.monitored_process.create_time()).isoformat()
                }
            except:
                status["monitored_process"] = {"status": "unavailable"}
        
        return status


def run_watchdog():
    """Run the watchdog as standalone script"""
    logger.info("=" * 60)
    logger.info("🐕 CyberGuardian Process Watchdog")
    logger.info("=" * 60)
    
    watchdog = ProcessWatchdog()
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info(f"📡 Received signal {signum}")
        watchdog.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    try:
        watchdog.monitor()
    except Exception as e:
        logger.error(f"❌ Fatal error in watchdog: {e}")
    finally:
        logger.info("👋 Watchdog shutdown complete")


if __name__ == "__main__":
    run_watchdog()