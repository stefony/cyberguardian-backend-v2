"""
CyberGuardian AI - Response Module
Automated Threat Response System

This module provides automated response capabilities:
- Threat blocking and coordination
- Process termination
- File quarantine
- Network isolation
- System rollback

Usage:
    from core.response import ThreatBlocker, ResponseMode
    
    blocker = ThreatBlocker(mode=ResponseMode.AUTOMATIC)
    blocker.respond_to_threat(threat_context)
"""

# Import main classes
from .threat_blocker import (
    ThreatBlocker,
    ThreatSeverity,
    ResponseAction,
    ResponseMode,
    ThreatContext,
    ResponseResult,
    ResponsePolicy,
    create_blocker
)

from .process_killer import (
    ProcessKiller,
    ProcessInfo,
    create_killer,
    handle_kill_process
)

from .quarantine import (
    FileQuarantine,
    QuarantineEntry,
    create_quarantine,
    handle_quarantine_file
)

from .network_isolation import (
    NetworkIsolation,
    RuleType,
    RuleDuration,
    FirewallRule,
    create_network_isolation,
    handle_block_network
)

from .rollback import (
    SystemRollback,
    Snapshot,
    FileVersion,
    create_rollback,
    handle_rollback_changes
)

# Version info
__version__ = '1.0.0'
__author__ = 'CyberGuardian AI Team'

# Export all public classes and functions
__all__ = [
    # Main classes
    'ThreatBlocker',
    'ProcessKiller',
    'FileQuarantine',
    'NetworkIsolation',
    'SystemRollback',
    
    # Enums
    'ThreatSeverity',
    'ResponseAction',
    'ResponseMode',
    'RuleType',
    'RuleDuration',
    
    # Data classes
    'ThreatContext',
    'ResponseResult',
    'ResponsePolicy',
    'ProcessInfo',
    'QuarantineEntry',
    'FirewallRule',
    'Snapshot',
    'FileVersion',
    
    # Factory functions
    'create_blocker',
    'create_killer',
    'create_quarantine',
    'create_network_isolation',
    'create_rollback',
    
    # Handler functions (for threat_blocker integration)
    'handle_kill_process',
    'handle_quarantine_file',
    'handle_block_network',
    'handle_rollback_changes',
]


def initialize_response_engine(mode=ResponseMode.AUTOMATIC):
    """
    Initialize complete response engine with all handlers registered.
    
    Args:
        mode: Response mode (AUTOMATIC, INTERACTIVE, PASSIVE)
        
    Returns:
        Configured ThreatBlocker instance
    """
    # Create threat blocker
    blocker = create_blocker(mode=mode)
    
    # Register all action handlers
    blocker.register_action_handler(ResponseAction.KILL_PROCESS, handle_kill_process)
    blocker.register_action_handler(ResponseAction.QUARANTINE_FILE, handle_quarantine_file)
    blocker.register_action_handler(ResponseAction.BLOCK_NETWORK, handle_block_network)
    blocker.register_action_handler(ResponseAction.ROLLBACK_CHANGES, handle_rollback_changes)
    
    # Start the worker thread
    blocker.start()
    
    return blocker


# Convenience function
def quick_response(threat_type, severity, target, **kwargs):
    """
    Quick threat response without creating ThreatContext manually.
    
    Args:
        threat_type: Type of threat (e.g., 'malware', 'ransomware')
        severity: Severity level (use ThreatSeverity enum)
        target: Dict with target info (pid, file_path, ip, etc.)
        **kwargs: Additional ThreatContext parameters
        
    Returns:
        List of ResponseResult objects
        
    Example:
        results = quick_response(
            threat_type='malware',
            severity=ThreatSeverity.HIGH,
            target={'pid': 1234, 'file_path': '/tmp/malware.exe'},
            confidence=0.95,
            source='detection/signature_scanner'
        )
    """
    import uuid
    from datetime import datetime
    
    # Create threat context
    threat = ThreatContext(
        threat_id=kwargs.get('threat_id', str(uuid.uuid4())),
        threat_type=threat_type,
        severity=severity,
        confidence=kwargs.get('confidence', 1.0),
        source=kwargs.get('source', 'manual'),
        target=target,
        mitre_technique=kwargs.get('mitre_technique'),
        indicators=kwargs.get('indicators'),
        timestamp=datetime.now()
    )
    
    # Create and use blocker
    blocker = initialize_response_engine(mode=ResponseMode.AUTOMATIC)
    results = blocker.respond_to_threat(threat)
    blocker.stop()
    
    return results