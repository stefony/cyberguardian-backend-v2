"""
CyberGuardian AI - Deception Module
Active Defense and Honeypot System

This module provides deception capabilities:
- Dynamic honeypot generation
- Realistic fake data creation
- Attacker profiling and tracking
- Forensic-quality logging
- Transparent attack redirection

Usage:
    from core.deception import HoneypotGenerator, AttackerTracker
    
    generator = HoneypotGenerator()
    generator.deploy_adaptive_honeypots(count=10)
    
    tracker = AttackerTracker()
    tracker.record_event(ip_address="203.0.113.42", event_type="file_access")
"""

# Import main classes
from .honeypot_generator import (
    HoneypotGenerator,
    HoneypotType,
    HoneypotPriority,
    Honeypot,
    create_honeypot_generator
)

from .fake_data_engine import (
    FakeDataEngine,
    create_fake_data_engine
)

from .attacker_tracker import (
    AttackerTracker,
    SkillLevel,
    AttackPhase,
    AttackEvent,
    AttackerProfile,
    create_attacker_tracker
)

from .deception_logger import (
    DeceptionLogger,
    LogLevel,
    ActivityType,
    DeceptionLogEntry,
    create_deception_logger
)

from .redirect_engine import (
    RedirectEngine,
    RedirectType,
    RedirectPriority,
    RedirectRule,
    create_redirect_engine
)

# Version info
__version__ = '1.0.0'
__author__ = 'CyberGuardian AI Team'

# Export all public classes and functions
__all__ = [
    # Main classes
    'HoneypotGenerator',
    'FakeDataEngine',
    'AttackerTracker',
    'DeceptionLogger',
    'RedirectEngine',
    
    # Enums
    'HoneypotType',
    'HoneypotPriority',
    'SkillLevel',
    'AttackPhase',
    'LogLevel',
    'ActivityType',
    'RedirectType',
    'RedirectPriority',
    
    # Data classes
    'Honeypot',
    'AttackEvent',
    'AttackerProfile',
    'DeceptionLogEntry',
    'RedirectRule',
    
    # Factory functions
    'create_honeypot_generator',
    'create_fake_data_engine',
    'create_attacker_tracker',
    'create_deception_logger',
    'create_redirect_engine',
]


def initialize_deception_system(honeypot_count: int = 20,
                               auto_redirect: bool = True) -> dict:
    """
    Initialize complete deception system with all components.
    
    Args:
        honeypot_count: Number of honeypots to deploy
        auto_redirect: Enable automatic redirects
        
    Returns:
        Dictionary with all initialized components
    """
    # Create all components
    generator = create_honeypot_generator()
    fake_data = create_fake_data_engine()
    tracker = create_attacker_tracker()
    logger = create_deception_logger()
    redirector = create_redirect_engine()
    
    # Deploy honeypots
    success, msg, details = generator.deploy_adaptive_honeypots(count=honeypot_count)
    print(f"🍯 Honeypots deployed: {details.get('deployed', 0)}")
    
    # Setup redirects if enabled
    if auto_redirect:
        success, msg, details = redirector.deploy_automatic_redirects(count=10)
        print(f"🔀 Redirects deployed: {details.get('deployed', 0)}")
    
    print("✅ Deception system initialized!")
    
    return {
        'generator': generator,
        'fake_data': fake_data,
        'tracker': tracker,
        'logger': logger,
        'redirector': redirector
    }


def quick_honeypot_setup(location: str = None) -> HoneypotGenerator:
    """
    Quick setup: Deploy honeypots in specified location.
    
    Args:
        location: Directory for honeypots (default: ~/.cyberguardian/honeypots)
        
    Returns:
        Configured HoneypotGenerator
        
    Example:
        generator = quick_honeypot_setup()
        # Honeypots automatically deployed
    """
    generator = create_honeypot_generator(honeypot_dir=location)
    
    # Deploy common honeypots
    generator.deploy_adaptive_honeypots(count=15)
    
    print(f"🍯 Quick setup complete: {len(generator.honeypots)} honeypots active")
    
    return generator


def track_attacker_session(ip_address: str, honeypot_id: str,
                          honeypot_name: str, activity_type: str,
                          **kwargs) -> dict:
    """
    Convenience function to track complete attacker interaction.
    
    Args:
        ip_address: Attacker IP
        honeypot_id: Honeypot ID
        honeypot_name: Honeypot name
        activity_type: Type of activity
        **kwargs: Additional details
        
    Returns:
        Dictionary with tracking results
        
    Example:
        track_attacker_session(
            ip_address="203.0.113.42",
            honeypot_id="HP_001",
            honeypot_name="passwords.txt",
            activity_type="file_read",
            command="cat passwords.txt"
        )
    """
    # Initialize components
    tracker = create_attacker_tracker()
    logger = create_deception_logger()
    
    # Record in tracker
    tracker.record_event(
        ip_address=ip_address,
        event_type=activity_type,
        target=honeypot_name,
        **kwargs
    )
    
    # Record in logger
    logger.log_activity(
        activity_type=ActivityType.FILE_ACCESS,  # Map as needed
        honeypot_id=honeypot_id,
        honeypot_name=honeypot_name,
        source_ip=ip_address,
        **kwargs
    )
    
    # Get attacker profile
    attacker_id = tracker._generate_attacker_id(ip_address)
    profile = tracker.get_attacker_profile(attacker_id)
    
    return {
        'attacker_id': attacker_id,
        'skill_level': profile.skill_level if profile else 'unknown',
        'total_events': profile.total_events if profile else 0,
        'tracked': True,
        'logged': True
    }