"""
CyberGuardian AI - Threat Blocker
Response Engine Coordinator

Coordinates automated threat response actions based on threat severity,
type, and system context. Implements the MITRE ATT&CK response framework.

Security Knowledge Applied:
- Incident Response procedures
- MITRE ATT&CK mitigation strategies
- Kill chain interruption
- Proportional response (не overreact)
"""

import logging
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
import threading
import queue
import json
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = 5    # Ransomware, Active C2, Data exfiltration
    HIGH = 4        # Known malware, Credential dumping
    MEDIUM = 3      # Suspicious behavior, Heuristic match
    LOW = 2         # Anomaly, Potential false positive
    INFO = 1        # Informational only


class ResponseAction(Enum):
    """Available response actions"""
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_NETWORK = "block_network"
    ISOLATE_SYSTEM = "isolate_system"
    ROLLBACK_CHANGES = "rollback_changes"
    ALERT_ONLY = "alert_only"


class ResponseMode(Enum):
    """Response automation levels"""
    AUTOMATIC = "automatic"      # Автоматично блокира всичко
    INTERACTIVE = "interactive"  # Пита потребителя за HIGH+
    PASSIVE = "passive"          # Само алерти, без действия


@dataclass
class ThreatContext:
    """Context information about a detected threat"""
    threat_id: str
    threat_type: str              # malware, ransomware, c2, phishing, etc.
    severity: ThreatSeverity
    confidence: float             # 0.0 - 1.0
    source: str                   # detection/signature_scanner, etc.
    target: Dict[str, Any]        # file_path, process_id, ip_address, etc.
    mitre_technique: Optional[str] = None
    indicators: Optional[Dict] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class ResponseResult:
    """Result of a response action"""
    action: ResponseAction
    success: bool
    message: str
    timestamp: datetime
    details: Optional[Dict] = None


class ResponsePolicy:
    """
    Defines response policies based on threat characteristics.
    Maps threat types to appropriate response actions.
    """
    
    def __init__(self):
        # Policy matrix: threat_type -> severity -> actions
        self.policies = {
            'ransomware': {
                ThreatSeverity.CRITICAL: [
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.ISOLATE_SYSTEM,
                    ResponseAction.ROLLBACK_CHANGES
                ],
                ThreatSeverity.HIGH: [
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.QUARANTINE_FILE
                ]
            },
            'malware': {
                ThreatSeverity.CRITICAL: [
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.QUARANTINE_FILE,
                    ResponseAction.BLOCK_NETWORK
                ],
                ThreatSeverity.HIGH: [
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.QUARANTINE_FILE
                ],
                ThreatSeverity.MEDIUM: [
                    ResponseAction.QUARANTINE_FILE
                ]
            },
            'c2_communication': {
                ThreatSeverity.CRITICAL: [
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.BLOCK_NETWORK,
                    ResponseAction.ISOLATE_SYSTEM
                ],
                ThreatSeverity.HIGH: [
                    ResponseAction.BLOCK_NETWORK,
                    ResponseAction.KILL_PROCESS
                ]
            },
            'credential_dumping': {
                ThreatSeverity.CRITICAL: [
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.ISOLATE_SYSTEM
                ],
                ThreatSeverity.HIGH: [
                    ResponseAction.KILL_PROCESS
                ]
            },
            'phishing': {
                ThreatSeverity.HIGH: [
                    ResponseAction.BLOCK_NETWORK
                ],
                ThreatSeverity.MEDIUM: [
                    ResponseAction.ALERT_ONLY
                ]
            },
            'suspicious_behavior': {
                ThreatSeverity.MEDIUM: [
                    ResponseAction.ALERT_ONLY
                ],
                ThreatSeverity.LOW: [
                    ResponseAction.ALERT_ONLY
                ]
            }
        }
        
        # Default policy for unknown threat types
        self.default_policy = {
            ThreatSeverity.CRITICAL: [ResponseAction.KILL_PROCESS, ResponseAction.ISOLATE_SYSTEM],
            ThreatSeverity.HIGH: [ResponseAction.KILL_PROCESS],
            ThreatSeverity.MEDIUM: [ResponseAction.ALERT_ONLY],
            ThreatSeverity.LOW: [ResponseAction.ALERT_ONLY],
            ThreatSeverity.INFO: [ResponseAction.ALERT_ONLY]
        }
    
    def get_actions(self, threat_type: str, severity: ThreatSeverity, confidence: float) -> List[ResponseAction]:
        """
        Determine appropriate response actions for a threat.
        
        Args:
            threat_type: Type of threat
            severity: Severity level
            confidence: Detection confidence (0.0-1.0)
            
        Returns:
            List of response actions to execute
        """
        # Get policy for threat type
        threat_policies = self.policies.get(threat_type, self.default_policy)
        actions = threat_policies.get(severity, [ResponseAction.ALERT_ONLY])
        
        # Adjust based on confidence
        if confidence < 0.7 and severity in [ThreatSeverity.MEDIUM, ThreatSeverity.LOW]:
            # Low confidence - only alert
            return [ResponseAction.ALERT_ONLY]
        
        return actions


class ThreatBlocker:
    """
    Main threat blocker coordinator.
    Manages threat response actions and execution.
    """
    
    def __init__(self, mode: ResponseMode = ResponseMode.AUTOMATIC):
        self.mode = mode
        self.policy = ResponsePolicy()
        self.action_queue = queue.Queue()
        self.response_history: List[ResponseResult] = []
        self.blocked_threats = 0
        self.running = False
        self.worker_thread = None
        
        # Action handlers (будем добавени от другите модули)
        self.action_handlers: Dict[ResponseAction, Callable] = {}
        
        # Statistics
        self.stats = {
            'total_threats': 0,
            'blocked_threats': 0,
            'quarantined_files': 0,
            'killed_processes': 0,
            'blocked_connections': 0,
            'false_positives': 0
        }
        
        logger.info(f"ThreatBlocker initialized in {mode.value} mode")
    
    def register_action_handler(self, action: ResponseAction, handler: Callable):
        """Register a handler function for a specific response action"""
        self.action_handlers[action] = handler
        logger.info(f"Registered handler for {action.value}")
    
    def start(self):
        """Start the response engine worker thread"""
        if self.running:
            logger.warning("ThreatBlocker already running")
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        logger.info("ThreatBlocker worker started")
    
    def stop(self):
        """Stop the response engine"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info("ThreatBlocker stopped")
    
    def respond_to_threat(self, threat: ThreatContext) -> List[ResponseResult]:
        """
        Main entry point for threat response.
        
        Args:
            threat: Threat context information
            
        Returns:
            List of response results
        """
        self.stats['total_threats'] += 1
        
        logger.warning(f"🚨 Responding to threat: {threat.threat_id} "
                      f"(type={threat.threat_type}, severity={threat.severity.name}, "
                      f"confidence={threat.confidence:.2f})")
        
        # Determine response actions
        actions = self.policy.get_actions(
            threat.threat_type,
            threat.severity,
            threat.confidence
        )
        
        # Check response mode
        if self.mode == ResponseMode.PASSIVE:
            logger.info("Passive mode - only alerting, no active response")
            return [self._create_result(ResponseAction.ALERT_ONLY, True, "Passive mode")]
        
        if self.mode == ResponseMode.INTERACTIVE and threat.severity.value >= ThreatSeverity.HIGH.value:
            logger.info("Interactive mode - user confirmation required for HIGH+ threats")
            # TODO: Integrate with UI for user confirmation
            # За сега продължаваме автоматично
        
        # Execute response actions
        results = []
        for action in actions:
            result = self._execute_action(action, threat)
            results.append(result)
            self.response_history.append(result)
            
            if result.success:
                self.stats['blocked_threats'] += 1
        
        # Log to audit trail
        self._log_response(threat, results)
        
        return results
    
    def _execute_action(self, action: ResponseAction, threat: ThreatContext) -> ResponseResult:
        """
        Execute a single response action.
        
        Args:
            action: Response action to execute
            threat: Threat context
            
        Returns:
            Response result
        """
        try:
            handler = self.action_handlers.get(action)
            
            if not handler:
                return self._create_result(
                    action,
                    False,
                    f"No handler registered for {action.value}"
                )
            
            # Execute the handler
            logger.info(f"Executing action: {action.value} for threat {threat.threat_id}")
            success, message, details = handler(threat)
            
            # Update statistics
            if success:
                if action == ResponseAction.QUARANTINE_FILE:
                    self.stats['quarantined_files'] += 1
                elif action == ResponseAction.KILL_PROCESS:
                    self.stats['killed_processes'] += 1
                elif action == ResponseAction.BLOCK_NETWORK:
                    self.stats['blocked_connections'] += 1
            
            return self._create_result(action, success, message, details)
            
        except Exception as e:
            logger.error(f"Error executing {action.value}: {e}")
            return self._create_result(
                action,
                False,
                f"Execution error: {str(e)}"
            )
    
    def _create_result(self, action: ResponseAction, success: bool, 
                      message: str, details: Optional[Dict] = None) -> ResponseResult:
        """Create a response result object"""
        return ResponseResult(
            action=action,
            success=success,
            message=message,
            timestamp=datetime.now(),
            details=details
        )
    
    def _log_response(self, threat: ThreatContext, results: List[ResponseResult]):
        """Log response actions to audit trail"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'threat_id': threat.threat_id,
            'threat_type': threat.threat_type,
            'severity': threat.severity.name,
            'confidence': threat.confidence,
            'actions': [
                {
                    'action': r.action.value,
                    'success': r.success,
                    'message': r.message
                }
                for r in results
            ]
        }
        
        # Save to audit log
        audit_file = "logs/response_audit.jsonl"
        os.makedirs("logs", exist_ok=True)
        
        with open(audit_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def _worker(self):
        """Background worker thread for processing queued actions"""
        logger.info("Response worker thread started")
        
        while self.running:
            try:
                # Get threat from queue (timeout to allow checking self.running)
                threat = self.action_queue.get(timeout=1.0)
                
                # Process the threat
                self.respond_to_threat(threat)
                
                self.action_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker thread error: {e}")
    
    def queue_response(self, threat: ThreatContext):
        """Add a threat to the response queue for async processing"""
        self.action_queue.put(threat)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get response engine statistics"""
        return self.stats.copy()
    
    def get_recent_responses(self, limit: int = 10) -> List[ResponseResult]:
        """Get recent response actions"""
        return self.response_history[-limit:]
    
    def whitelist_add(self, identifier: str, identifier_type: str):
        """
        Add item to whitelist (will not be blocked)
        
        Args:
            identifier: Hash, process name, IP, etc.
            identifier_type: 'hash', 'process', 'ip', 'domain'
        """
        # TODO: Implement whitelist management
        logger.info(f"Added to whitelist: {identifier_type}={identifier}")
    
    def rollback_action(self, response_result: ResponseResult) -> bool:
        """
        Rollback a previously executed action (undo false positive)
        
        Args:
            response_result: The result to rollback
            
        Returns:
            True if rollback successful
        """
        try:
            logger.info(f"Rolling back action: {response_result.action.value}")
            
            # TODO: Implement action-specific rollback
            # - KILL_PROCESS: Cannot undo (would need to restart)
            # - QUARANTINE_FILE: Restore from quarantine
            # - BLOCK_NETWORK: Remove firewall rule
            
            self.stats['false_positives'] += 1
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False


def create_blocker(mode: ResponseMode = ResponseMode.AUTOMATIC) -> ThreatBlocker:
    """Factory function to create and configure a ThreatBlocker instance"""
    blocker = ThreatBlocker(mode=mode)
    return blocker


# Example usage and testing
if __name__ == "__main__":
    print("🛡️ CyberGuardian - Threat Blocker Test\n")
    
    # Create blocker
    blocker = create_blocker(mode=ResponseMode.AUTOMATIC)
    
    # Mock action handlers for testing
    def mock_kill_process(threat):
        return True, f"Process {threat.target.get('pid')} terminated", {}
    
    def mock_quarantine(threat):
        return True, f"File {threat.target.get('file')} quarantined", {}
    
    def mock_block_network(threat):
        return True, f"Blocked connection to {threat.target.get('ip')}", {}
    
    # Register handlers
    blocker.register_action_handler(ResponseAction.KILL_PROCESS, mock_kill_process)
    blocker.register_action_handler(ResponseAction.QUARANTINE_FILE, mock_quarantine)
    blocker.register_action_handler(ResponseAction.BLOCK_NETWORK, mock_block_network)
    
    # Test scenarios
    print("Test 1: Ransomware detection")
    ransomware_threat = ThreatContext(
        threat_id="THR-001",
        threat_type="ransomware",
        severity=ThreatSeverity.CRITICAL,
        confidence=0.95,
        source="detection/behavioral_engine",
        target={'pid': 1234, 'file': 'C:\\malware.exe'},
        mitre_technique="T1486"
    )
    
    results = blocker.respond_to_threat(ransomware_threat)
    print(f"✅ Actions executed: {len(results)}")
    for result in results:
        print(f"  - {result.action.value}: {result.message}")
    
    print("\nTest 2: Medium severity suspicious behavior")
    suspicious_threat = ThreatContext(
        threat_id="THR-002",
        threat_type="suspicious_behavior",
        severity=ThreatSeverity.MEDIUM,
        confidence=0.65,
        source="detection/heuristic_engine",
        target={'pid': 5678}
    )
    
    results = blocker.respond_to_threat(suspicious_threat)
    print(f"✅ Actions executed: {len(results)}")
    for result in results:
        print(f"  - {result.action.value}: {result.message}")
    
    print("\n📊 Statistics:")
    stats = blocker.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ Threat Blocker test complete!")