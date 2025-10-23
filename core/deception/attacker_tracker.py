"""
CyberGuardian AI - Attacker Tracker
Attacker Profiling and Attribution System

Tracks and profiles attackers by:
- Recording all actions
- Identifying TTPs (Tactics, Techniques, Procedures)
- Skill level assessment
- Tool fingerprinting
- Attribution indicators
- Timeline generation

Security Knowledge Applied:
- MITRE ATT&CK framework
- Threat actor profiling
- Digital forensics
- Attribution techniques
- Behavioral analysis
"""

import logging
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SkillLevel(Enum):
    """Attacker skill level assessment"""
    SCRIPT_KIDDIE = 1      # Using automated tools, no customization
    INTERMEDIATE = 2       # Some customization, basic evasion
    ADVANCED = 3           # Custom tools, good evasion techniques
    EXPERT = 4             # Sophisticated attacks, advanced evasion
    APT = 5               # Nation-state level, very sophisticated


class AttackPhase(Enum):
    """MITRE ATT&CK kill chain phases"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class AttackEvent:
    """Single attack event/action"""
    event_id: str
    timestamp: str
    event_type: str              # file_access, network_connection, command, etc.
    source_ip: Optional[str] = None
    target: Optional[str] = None
    command: Optional[str] = None
    tool_used: Optional[str] = None
    mitre_technique: Optional[str] = None
    success: bool = False
    details: Dict = field(default_factory=dict)


@dataclass
class AttackerProfile:
    """Complete attacker profile"""
    attacker_id: str
    first_seen: str
    last_seen: str
    ip_addresses: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    attack_phases: List[str] = field(default_factory=list)
    skill_level: str = "unknown"
    total_events: int = 0
    successful_events: int = 0
    honeypots_triggered: List[str] = field(default_factory=list)
    iocs: Dict = field(default_factory=dict)  # Indicators of Compromise
    notes: str = ""


class AttackerTracker:
    """
    Tracks and profiles attackers based on their actions.
    """
    
    # Tool fingerprints for identification
    TOOL_SIGNATURES = {
        'nmap': ['nmap', 'scan', 'port scan'],
        'metasploit': ['msf', 'meterpreter', 'metasploit'],
        'mimikatz': ['mimikatz', 'sekurlsa', 'lsadump'],
        'powershell_empire': ['empire', 'invoke-', 'powershell'],
        'cobalt_strike': ['beacon', 'cobalt', 'cs.exe'],
        'sqlmap': ['sqlmap', 'sql injection'],
        'hydra': ['hydra', 'brute force'],
        'nikto': ['nikto', 'web scanner'],
        'burp': ['burp', 'intruder'],
        'custom_script': ['python', 'curl', 'wget']
    }
    
    # Skill indicators
    SCRIPT_KIDDIE_INDICATORS = [
        'default settings', 'obvious scan', 'no evasion',
        'automated tool', 'common exploit'
    ]
    
    ADVANCED_INDICATORS = [
        'custom payload', 'obfuscation', 'anti-forensics',
        'living off the land', 'fileless', 'memory-only'
    ]
    
    def __init__(self, tracking_dir: str = None):
        """
        Initialize attacker tracker.
        
        Args:
            tracking_dir: Directory for tracking data
        """
        # Setup tracking directory
        if tracking_dir:
            self.tracking_dir = Path(tracking_dir)
        else:
            home = Path.home()
            self.tracking_dir = home / '.cyberguardian' / 'attacker_tracking'
        
        self.tracking_dir.mkdir(parents=True, exist_ok=True)
        
        # Attacker profiles
        self.profiles: Dict[str, AttackerProfile] = {}
        self.events: Dict[str, List[AttackEvent]] = {}  # attacker_id -> events
        
        # Metadata files
        self.profiles_file = self.tracking_dir / 'attacker_profiles.json'
        self.events_file = self.tracking_dir / 'attack_events.json'
        
        # Statistics
        self.stats = {
            'total_attackers': 0,
            'total_events': 0,
            'active_sessions': 0,
            'honeypots_triggered': 0,
            'tools_identified': 0
        }
        
        # Load existing data
        self._load_data()
        
        logger.info(f"AttackerTracker initialized at {self.tracking_dir}")
        logger.info(f"Tracking {len(self.profiles)} attackers")
    
    def _load_data(self):
        """Load attacker profiles and events"""
        # Load profiles
        if self.profiles_file.exists():
            try:
                with open(self.profiles_file, 'r') as f:
                    data = json.load(f)
                
                for aid, profile_dict in data.items():
                    self.profiles[aid] = AttackerProfile(**profile_dict)
                
                logger.debug(f"Loaded {len(self.profiles)} attacker profiles")
            except Exception as e:
                logger.error(f"Failed to load profiles: {e}")
        
        # Load events
        if self.events_file.exists():
            try:
                with open(self.events_file, 'r') as f:
                    data = json.load(f)
                
                for aid, events_list in data.items():
                    self.events[aid] = [AttackEvent(**event) for event in events_list]
                
                logger.debug(f"Loaded events for {len(self.events)} attackers")
            except Exception as e:
                logger.error(f"Failed to load events: {e}")
    
    def _save_data(self):
        """Save attacker profiles and events"""
        try:
            # Save profiles
            profiles_data = {aid: asdict(profile) for aid, profile in self.profiles.items()}
            with open(self.profiles_file, 'w') as f:
                json.dump(profiles_data, f, indent=2)
            
            # Save events
            events_data = {
                aid: [asdict(event) for event in events]
                for aid, events in self.events.items()
            }
            with open(self.events_file, 'w') as f:
                json.dump(events_data, f, indent=2)
            
            logger.debug("Attacker data saved")
        except Exception as e:
            logger.error(f"Failed to save data: {e}")
    
    def _generate_attacker_id(self, ip_address: str) -> str:
        """Generate attacker ID from IP (hashed for privacy)"""
        # Hash IP for anonymization
        hash_obj = hashlib.sha256(ip_address.encode())
        return f"ATK_{hash_obj.hexdigest()[:16]}"
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return f"EVT_{timestamp}"
    
    def record_event(self, ip_address: str, event_type: str,
                    target: str = None, command: str = None,
                    tool_used: str = None, success: bool = False,
                    **kwargs) -> Tuple[bool, str]:
        """
        Record an attack event.
        
        Args:
            ip_address: Source IP of attacker
            event_type: Type of event (file_access, network_scan, etc.)
            target: Target of attack
            command: Command executed (if applicable)
            tool_used: Tool identified
            success: Whether attack was successful
            **kwargs: Additional event details
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Get or create attacker profile
            attacker_id = self._generate_attacker_id(ip_address)
            
            if attacker_id not in self.profiles:
                # New attacker - create profile
                profile = AttackerProfile(
                    attacker_id=attacker_id,
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    ip_addresses=[ip_address]
                )
                self.profiles[attacker_id] = profile
                self.events[attacker_id] = []
                
                self.stats['total_attackers'] += 1
                logger.warning(f"🚨 NEW ATTACKER DETECTED: {attacker_id} from {ip_address}")
            else:
                profile = self.profiles[attacker_id]
                profile.last_seen = datetime.now().isoformat()
                
                # Update IP list if new
                if ip_address not in profile.ip_addresses:
                    profile.ip_addresses.append(ip_address)
            
            # Create event
            event = AttackEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.now().isoformat(),
                event_type=event_type,
                source_ip=ip_address,
                target=target,
                command=command,
                tool_used=tool_used,
                success=success,
                details=kwargs
            )
            
            # Add to events
            self.events[attacker_id].append(event)
            
            # Update profile
            profile.total_events += 1
            if success:
                profile.successful_events += 1
            
            # Identify tool if not provided
            if not tool_used and command:
                tool_used = self._identify_tool(command)
                event.tool_used = tool_used
            
            if tool_used and tool_used not in profile.tools_used:
                profile.tools_used.append(tool_used)
            
            # Extract MITRE technique
            mitre_technique = kwargs.get('mitre_technique')
            if mitre_technique and mitre_technique not in profile.mitre_techniques:
                profile.mitre_techniques.append(mitre_technique)
            
            # Assess skill level
            profile.skill_level = self._assess_skill_level(attacker_id)
            
            # Save data
            self._save_data()
            
            self.stats['total_events'] += 1
            
            logger.info(f"📝 Event recorded: {event_type} from {attacker_id}")
            
            return True, f"Event recorded for {attacker_id}"
            
        except Exception as e:
            error_msg = f"Failed to record event: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def _identify_tool(self, command: str) -> Optional[str]:
        """Identify tool based on command/pattern"""
        command_lower = command.lower()
        
        for tool, signatures in self.TOOL_SIGNATURES.items():
            if any(sig in command_lower for sig in signatures):
                return tool
        
        return "unknown"
    
    def _assess_skill_level(self, attacker_id: str) -> str:
        """
        Assess attacker skill level based on behavior.
        
        Args:
            attacker_id: Attacker ID
            
        Returns:
            Skill level as string
        """
        if attacker_id not in self.profiles:
            return "unknown"
        
        profile = self.profiles[attacker_id]
        events = self.events.get(attacker_id, [])
        
        if not events:
            return "unknown"
        
        score = 0
        
        # Factor 1: Tool diversity
        unique_tools = len(set(profile.tools_used))
        if unique_tools > 5:
            score += 2
        elif unique_tools > 2:
            score += 1
        
        # Factor 2: Custom tools/scripts
        if 'custom_script' in profile.tools_used:
            score += 2
        
        # Factor 3: Evasion techniques
        evasion_count = sum(1 for e in events if 'obfuscation' in str(e.details) or 'evasion' in str(e.details))
        if evasion_count > 3:
            score += 2
        elif evasion_count > 0:
            score += 1
        
        # Factor 4: Success rate
        success_rate = profile.successful_events / profile.total_events if profile.total_events > 0 else 0
        if success_rate > 0.7:
            score += 2
        elif success_rate > 0.4:
            score += 1
        
        # Factor 5: MITRE technique diversity
        if len(profile.mitre_techniques) > 5:
            score += 2
        elif len(profile.mitre_techniques) > 2:
            score += 1
        
        # Determine skill level
        if score >= 8:
            return SkillLevel.APT.name
        elif score >= 6:
            return SkillLevel.EXPERT.name
        elif score >= 4:
            return SkillLevel.ADVANCED.name
        elif score >= 2:
            return SkillLevel.INTERMEDIATE.name
        else:
            return SkillLevel.SCRIPT_KIDDIE.name
    
    def record_honeypot_access(self, ip_address: str, honeypot_id: str,
                               honeypot_name: str) -> bool:
        """Record honeypot access"""
        attacker_id = self._generate_attacker_id(ip_address)
        
        if attacker_id in self.profiles:
            profile = self.profiles[attacker_id]
            
            honeypot_info = f"{honeypot_name} ({honeypot_id})"
            if honeypot_info not in profile.honeypots_triggered:
                profile.honeypots_triggered.append(honeypot_info)
            
            self.stats['honeypots_triggered'] += 1
            self._save_data()
            
            logger.warning(f"🍯 Attacker {attacker_id} accessed honeypot: {honeypot_name}")
            return True
        
        return False
    
    def add_ioc(self, attacker_id: str, ioc_type: str, ioc_value: str):
        """
        Add Indicator of Compromise to attacker profile.
        
        Args:
            attacker_id: Attacker ID
            ioc_type: Type of IOC (hash, domain, ip, url, etc.)
            ioc_value: IOC value
        """
        if attacker_id not in self.profiles:
            return
        
        profile = self.profiles[attacker_id]
        
        if ioc_type not in profile.iocs:
            profile.iocs[ioc_type] = []
        
        if ioc_value not in profile.iocs[ioc_type]:
            profile.iocs[ioc_type].append(ioc_value)
        
        self._save_data()
        logger.info(f"📌 IOC added: {ioc_type}={ioc_value} for {attacker_id}")
    
    def get_attacker_profile(self, attacker_id: str) -> Optional[AttackerProfile]:
        """Get complete attacker profile"""
        return self.profiles.get(attacker_id)
    
    def get_attacker_timeline(self, attacker_id: str) -> List[AttackEvent]:
        """Get chronological timeline of attacker actions"""
        events = self.events.get(attacker_id, [])
        return sorted(events, key=lambda e: e.timestamp)
    
    def get_active_attackers(self, hours: int = 24) -> List[AttackerProfile]:
        """
        Get attackers active within specified hours.
        
        Args:
            hours: Time window in hours
            
        Returns:
            List of active attacker profiles
        """
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(hours=hours)
        active = []
        
        for profile in self.profiles.values():
            last_seen = datetime.fromisoformat(profile.last_seen)
            if last_seen > cutoff:
                active.append(profile)
        
        return sorted(active, key=lambda p: p.last_seen, reverse=True)
    
    def get_top_attackers(self, limit: int = 10) -> List[Tuple[str, AttackerProfile]]:
        """Get top attackers by event count"""
        sorted_attackers = sorted(
            self.profiles.items(),
            key=lambda x: x[1].total_events,
            reverse=True
        )
        return sorted_attackers[:limit]
    
    def generate_threat_report(self, attacker_id: str) -> Dict:
        """
        Generate comprehensive threat report for an attacker.
        
        Args:
            attacker_id: Attacker ID
            
        Returns:
            Threat report dictionary
        """
        if attacker_id not in self.profiles:
            return {}
        
        profile = self.profiles[attacker_id]
        events = self.events.get(attacker_id, [])
        
        report = {
            'attacker_id': attacker_id,
            'skill_level': profile.skill_level,
            'first_seen': profile.first_seen,
            'last_seen': profile.last_seen,
            'duration_days': (datetime.fromisoformat(profile.last_seen) - 
                             datetime.fromisoformat(profile.first_seen)).days,
            'total_events': profile.total_events,
            'successful_events': profile.successful_events,
            'success_rate': round(profile.successful_events / profile.total_events * 100, 2) if profile.total_events > 0 else 0,
            'ip_addresses': profile.ip_addresses,
            'tools_used': profile.tools_used,
            'mitre_techniques': profile.mitre_techniques,
            'honeypots_triggered': profile.honeypots_triggered,
            'iocs': profile.iocs,
            'timeline': [
                {
                    'timestamp': e.timestamp,
                    'type': e.event_type,
                    'target': e.target,
                    'success': e.success
                }
                for e in sorted(events, key=lambda x: x.timestamp)[-10:]  # Last 10 events
            ]
        }
        
        return report
    
    def get_statistics(self) -> Dict:
        """Get tracking statistics"""
        self.stats['total_attackers'] = len(self.profiles)
        self.stats['active_sessions'] = len(self.get_active_attackers(hours=1))
        return self.stats.copy()
    
    def export_attacker_data(self, attacker_id: str, export_path: str) -> bool:
        """Export all data for an attacker to JSON file"""
        try:
            report = self.generate_threat_report(attacker_id)
            
            with open(export_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Attacker data exported to {export_path}")
            return True
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


def create_attacker_tracker(tracking_dir: str = None) -> AttackerTracker:
    """Factory function to create AttackerTracker instance"""
    return AttackerTracker(tracking_dir=tracking_dir)


# Testing
if __name__ == "__main__":
    print("🎯 CyberGuardian - Attacker Tracker Test\n")
    
    tracker = create_attacker_tracker()
    
    print(f"📂 Tracking directory: {tracker.tracking_dir}")
    
    # Simulate attacker activity
    test_ip = "203.0.113.42"
    
    print("\n🎯 Test 1: Record reconnaissance event")
    success, msg = tracker.record_event(
        ip_address=test_ip,
        event_type="port_scan",
        target="192.168.1.1",
        tool_used="nmap",
        command="nmap -sS -p- 192.168.1.1",
        success=True
    )
    print(f"   {'✅' if success else '❌'} {msg}")
    
    print("\n🎯 Test 2: Record file access event")
    success, msg = tracker.record_event(
        ip_address=test_ip,
        event_type="file_access",
        target="/home/admin/passwords.txt",
        success=True
    )
    print(f"   {'✅' if success else '❌'} {msg}")
    
    print("\n🎯 Test 3: Record honeypot access")
    attacker_id = tracker._generate_attacker_id(test_ip)
    success = tracker.record_honeypot_access(
        ip_address=test_ip,
        honeypot_id="HP_001",
        honeypot_name="passwords.txt"
    )
    print(f"   {'✅' if success else '❌'} Honeypot access recorded")
    
    print("\n📊 Test 4: Get attacker profile")
    profile = tracker.get_attacker_profile(attacker_id)
    if profile:
        print(f"   Attacker ID: {profile.attacker_id}")
        print(f"   Skill Level: {profile.skill_level}")
        print(f"   Total Events: {profile.total_events}")
        print(f"   Tools Used: {profile.tools_used}")
        print(f"   Honeypots: {len(profile.honeypots_triggered)}")
    
    print("\n📋 Test 5: Generate threat report")
    report = tracker.generate_threat_report(attacker_id)
    print(f"   Success Rate: {report.get('success_rate', 0)}%")
    print(f"   Duration: {report.get('duration_days', 0)} days")
    
    print("\n📊 Statistics:")
    stats = tracker.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n✅ Attacker Tracker test complete!")
    print(f"\n⚠️  Tracking data saved at: {tracker.tracking_dir}")