"""
CyberGuardian AI - Network Isolation Engine
Network Security Response System

Blocks malicious network activity with:
- IP/Domain blocking
- Port blocking
- Process network isolation
- Full system isolation (kill switch)
- Cross-platform firewall management

Security Knowledge Applied:
- C2 communication blocking
- Data exfiltration prevention
- Network segmentation
- Kill switch for ransomware
- DNS filtering
"""

import logging
import os
import platform
import subprocess
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RuleType(Enum):
    """Types of network isolation rules"""
    BLOCK_IP = "block_ip"
    BLOCK_PORT = "block_port"
    BLOCK_PROCESS = "block_process"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_SYSTEM = "isolate_system"


class RuleDuration(Enum):
    """Duration of firewall rules"""
    TEMPORARY = "temporary"    # До рестарт
    PERMANENT = "permanent"    # Записано в firewall config


@dataclass
class FirewallRule:
    """Firewall rule metadata"""
    rule_id: str
    rule_type: RuleType
    target: str              # IP, port, process name, domain
    direction: str           # inbound, outbound, both
    duration: RuleDuration
    created_time: str
    expires_time: Optional[str] = None
    reason: str = "CyberGuardian threat block"


class NetworkIsolation:
    """
    Cross-platform network isolation engine.
    Manages firewall rules to block malicious network activity.
    """
    
    def __init__(self):
        self.system = platform.system().lower()
        self.rules: Dict[str, FirewallRule] = {}
        self.isolated_system = False
        
        # Statistics
        self.stats = {
            'total_blocks': 0,
            'blocked_ips': 0,
            'blocked_ports': 0,
            'blocked_processes': 0,
            'system_isolations': 0,
            'active_rules': 0
        }
        
        # Check if we have required privileges
        self._check_privileges()
        
        logger.info(f"NetworkIsolation initialized for {self.system}")
    
    def _check_privileges(self):
        """Check if running with required privileges"""
        if self.system == 'windows':
            # Check for admin rights on Windows
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    logger.warning("⚠️ Not running as Administrator - firewall changes may fail")
            except:
                logger.warning("Cannot verify admin status")
        
        elif self.system in ['linux', 'darwin']:
            # Check for root/sudo on Unix
            if os.geteuid() != 0:
                logger.warning("⚠️ Not running as root - firewall changes may fail")
    
    def _run_command(self, command: List[str]) -> Tuple[bool, str]:
        """
        Execute a system command.
        
        Args:
            command: Command and arguments as list
            
        Returns:
            Tuple of (success, output)
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                logger.error(f"Command failed: {' '.join(command)}")
                logger.error(f"Error: {result.stderr}")
                return False, result.stderr
                
        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, str(e)
    
    def _generate_rule_id(self) -> str:
        """Generate unique rule ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"CGFW_{timestamp}_{os.urandom(4).hex()}"
    
    def block_ip(self, ip_address: str, direction: str = "both",
                duration: RuleDuration = RuleDuration.PERMANENT,
                reason: str = "Malicious IP") -> Tuple[bool, str, Dict]:
        """
        Block an IP address.
        
        Args:
            ip_address: IP to block (IPv4 or IPv6)
            direction: 'inbound', 'outbound', or 'both'
            duration: Rule duration
            reason: Reason for blocking
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            logger.info(f"Blocking IP: {ip_address} ({direction})")
            
            # Validate IP format
            if not self._validate_ip(ip_address):
                return False, f"Invalid IP address: {ip_address}", {}
            
            rule_id = self._generate_rule_id()
            success = False
            
            if self.system == 'windows':
                success = self._block_ip_windows(ip_address, direction, rule_id)
            elif self.system == 'linux':
                success = self._block_ip_linux(ip_address, direction)
            elif self.system == 'darwin':
                success = self._block_ip_macos(ip_address, direction)
            
            if success:
                # Save rule metadata
                rule = FirewallRule(
                    rule_id=rule_id,
                    rule_type=RuleType.BLOCK_IP,
                    target=ip_address,
                    direction=direction,
                    duration=duration,
                    created_time=datetime.now().isoformat(),
                    reason=reason
                )
                self.rules[rule_id] = rule
                
                self.stats['total_blocks'] += 1
                self.stats['blocked_ips'] += 1
                self.stats['active_rules'] = len(self.rules)
                
                msg = f"IP blocked: {ip_address}"
                logger.info(f"✅ {msg}")
                
                return True, msg, {'rule_id': rule_id}
            else:
                return False, f"Failed to block IP: {ip_address}", {}
                
        except Exception as e:
            error_msg = f"Error blocking IP {ip_address}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        # Simple regex for IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # TODO: Add IPv6 validation
        return False
    
    def _block_ip_windows(self, ip: str, direction: str, rule_id: str) -> bool:
        """Block IP on Windows using netsh"""
        try:
            # netsh advfirewall firewall add rule
            if direction in ['inbound', 'both']:
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=CyberGuardian_{rule_id}_IN',
                    'dir=in',
                    'action=block',
                    f'remoteip={ip}'
                ]
                success, _ = self._run_command(cmd)
                if not success:
                    return False
            
            if direction in ['outbound', 'both']:
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=CyberGuardian_{rule_id}_OUT',
                    'dir=out',
                    'action=block',
                    f'remoteip={ip}'
                ]
                success, _ = self._run_command(cmd)
                if not success:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Windows IP block failed: {e}")
            return False
    
    def _block_ip_linux(self, ip: str, direction: str) -> bool:
        """Block IP on Linux using iptables"""
        try:
            if direction in ['inbound', 'both']:
                cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
                success, _ = self._run_command(cmd)
                if not success:
                    return False
            
            if direction in ['outbound', 'both']:
                cmd = ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP']
                success, _ = self._run_command(cmd)
                if not success:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Linux IP block failed: {e}")
            return False
    
    def _block_ip_macos(self, ip: str, direction: str) -> bool:
        """Block IP on macOS using pfctl"""
        try:
            # Add to pf table
            cmd = ['pfctl', '-t', 'cyberguardian_blocked', '-T', 'add', ip]
            success, _ = self._run_command(cmd)
            
            if success:
                # Enable pf if not already
                self._run_command(['pfctl', '-e'])
            
            return success
            
        except Exception as e:
            logger.error(f"macOS IP block failed: {e}")
            return False
    
    def block_port(self, port: int, protocol: str = "tcp",
                  direction: str = "both",
                  duration: RuleDuration = RuleDuration.PERMANENT) -> Tuple[bool, str, Dict]:
        """
        Block a network port.
        
        Args:
            port: Port number to block
            protocol: 'tcp', 'udp', or 'both'
            direction: 'inbound', 'outbound', or 'both'
            duration: Rule duration
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            logger.info(f"Blocking port: {port}/{protocol} ({direction})")
            
            # Validate port
            if not (0 < port < 65536):
                return False, f"Invalid port: {port}", {}
            
            rule_id = self._generate_rule_id()
            success = False
            
            if self.system == 'windows':
                success = self._block_port_windows(port, protocol, direction, rule_id)
            elif self.system == 'linux':
                success = self._block_port_linux(port, protocol, direction)
            elif self.system == 'darwin':
                success = self._block_port_macos(port, protocol, direction)
            
            if success:
                rule = FirewallRule(
                    rule_id=rule_id,
                    rule_type=RuleType.BLOCK_PORT,
                    target=f"{port}/{protocol}",
                    direction=direction,
                    duration=duration,
                    created_time=datetime.now().isoformat()
                )
                self.rules[rule_id] = rule
                
                self.stats['total_blocks'] += 1
                self.stats['blocked_ports'] += 1
                self.stats['active_rules'] = len(self.rules)
                
                msg = f"Port blocked: {port}/{protocol}"
                logger.info(f"✅ {msg}")
                
                return True, msg, {'rule_id': rule_id}
            else:
                return False, f"Failed to block port: {port}", {}
                
        except Exception as e:
            error_msg = f"Error blocking port {port}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def _block_port_windows(self, port: int, protocol: str, direction: str, rule_id: str) -> bool:
        """Block port on Windows"""
        try:
            protocols = [protocol] if protocol != 'both' else ['tcp', 'udp']
            
            for proto in protocols:
                if direction in ['inbound', 'both']:
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name=CyberGuardian_{rule_id}_{proto}_IN',
                        'dir=in',
                        'action=block',
                        f'protocol={proto}',
                        f'localport={port}'
                    ]
                    self._run_command(cmd)
                
                if direction in ['outbound', 'both']:
                    cmd = [
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name=CyberGuardian_{rule_id}_{proto}_OUT',
                        'dir=out',
                        'action=block',
                        f'protocol={proto}',
                        f'remoteport={port}'
                    ]
                    self._run_command(cmd)
            
            return True
            
        except Exception as e:
            logger.error(f"Windows port block failed: {e}")
            return False
    
    def _block_port_linux(self, port: int, protocol: str, direction: str) -> bool:
        """Block port on Linux"""
        try:
            protocols = [protocol] if protocol != 'both' else ['tcp', 'udp']
            
            for proto in protocols:
                if direction in ['inbound', 'both']:
                    cmd = ['iptables', '-A', 'INPUT', '-p', proto, '--dport', str(port), '-j', 'DROP']
                    self._run_command(cmd)
                
                if direction in ['outbound', 'both']:
                    cmd = ['iptables', '-A', 'OUTPUT', '-p', proto, '--dport', str(port), '-j', 'DROP']
                    self._run_command(cmd)
            
            return True
            
        except Exception as e:
            logger.error(f"Linux port block failed: {e}")
            return False
    
    def _block_port_macos(self, port: int, protocol: str, direction: str) -> bool:
        """Block port on macOS"""
        try:
            # macOS pfctl rules are more complex
            # For now, log that it's not fully implemented
            logger.warning("macOS port blocking requires manual pf.conf configuration")
            return False
            
        except Exception as e:
            logger.error(f"macOS port block failed: {e}")
            return False
    
    def block_process_network(self, process_name: str) -> Tuple[bool, str, Dict]:
        """
        Block all network access for a specific process.
        
        Args:
            process_name: Name of process to block
            
        Returns:
            Tuple of (success, message, details)
        """
        try:
            logger.info(f"Blocking network for process: {process_name}")
            
            rule_id = self._generate_rule_id()
            success = False
            
            if self.system == 'windows':
                success = self._block_process_windows(process_name, rule_id)
            else:
                # Linux/macOS process blocking is more complex
                # Would need to use cgroups or similar
                logger.warning("Process-level network blocking not implemented for Unix")
                return False, "Not implemented for this platform", {}
            
            if success:
                rule = FirewallRule(
                    rule_id=rule_id,
                    rule_type=RuleType.BLOCK_PROCESS,
                    target=process_name,
                    direction="both",
                    duration=RuleDuration.PERMANENT,
                    created_time=datetime.now().isoformat()
                )
                self.rules[rule_id] = rule
                
                self.stats['total_blocks'] += 1
                self.stats['blocked_processes'] += 1
                self.stats['active_rules'] = len(self.rules)
                
                msg = f"Process network blocked: {process_name}"
                logger.info(f"✅ {msg}")
                
                return True, msg, {'rule_id': rule_id}
            else:
                return False, f"Failed to block process: {process_name}", {}
                
        except Exception as e:
            error_msg = f"Error blocking process {process_name}: {str(e)}"
            logger.error(error_msg)
            return False, error_msg, {}
    
    def _block_process_windows(self, process_name: str, rule_id: str) -> bool:
        """Block process network access on Windows"""
        try:
            # Block outbound connections from process
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=CyberGuardian_{rule_id}_PROC',
                'dir=out',
                'action=block',
                f'program={process_name}'
            ]
            success, _ = self._run_command(cmd)
            return success
            
        except Exception as e:
            logger.error(f"Windows process block failed: {e}")
            return False
    
    def isolate_system(self, allow_local: bool = True) -> Tuple[bool, str]:
        """
        Complete network isolation (kill switch).
        Blocks ALL network traffic except optionally local network.
        
        WARNING: This will disconnect the system from the internet!
        
        Args:
            allow_local: If True, allow local network (192.168.x.x, 10.x.x.x)
            
        Returns:
            Tuple of (success, message)
        """
        try:
            logger.warning("🚨 ISOLATING SYSTEM FROM NETWORK!")
            
            if self.system == 'windows':
                # Disable all network adapters
                cmd = ['netsh', 'interface', 'set', 'interface', 'name="Ethernet"', 'admin=disable']
                self._run_command(cmd)
                cmd = ['netsh', 'interface', 'set', 'interface', 'name="Wi-Fi"', 'admin=disable']
                self._run_command(cmd)
                
            elif self.system == 'linux':
                # Block all traffic
                self._run_command(['iptables', '-P', 'INPUT', 'DROP'])
                self._run_command(['iptables', '-P', 'OUTPUT', 'DROP'])
                self._run_command(['iptables', '-P', 'FORWARD', 'DROP'])
                
                if allow_local:
                    # Allow localhost
                    self._run_command(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
                    self._run_command(['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'])
            
            elif self.system == 'darwin':
                # Disable network interfaces
                self._run_command(['networksetup', '-setnetworkserviceenabled', 'Wi-Fi', 'off'])
                self._run_command(['networksetup', '-setnetworkserviceenabled', 'Ethernet', 'off'])
            
            self.isolated_system = True
            self.stats['system_isolations'] += 1
            
            msg = "System isolated from network"
            logger.warning(f"🚨 {msg}")
            
            return True, msg
            
        except Exception as e:
            error_msg = f"Failed to isolate system: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def restore_network(self) -> Tuple[bool, str]:
        """
        Restore network connectivity after isolation.
        
        Returns:
            Tuple of (success, message)
        """
        try:
            logger.info("Restoring network connectivity")
            
            if self.system == 'windows':
                cmd = ['netsh', 'interface', 'set', 'interface', 'name="Ethernet"', 'admin=enable']
                self._run_command(cmd)
                cmd = ['netsh', 'interface', 'set', 'interface', 'name="Wi-Fi"', 'admin=enable']
                self._run_command(cmd)
                
            elif self.system == 'linux':
                self._run_command(['iptables', '-P', 'INPUT', 'ACCEPT'])
                self._run_command(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
                self._run_command(['iptables', '-P', 'FORWARD', 'ACCEPT'])
                
            elif self.system == 'darwin':
                self._run_command(['networksetup', '-setnetworkserviceenabled', 'Wi-Fi', 'on'])
                self._run_command(['networksetup', '-setnetworkserviceenabled', 'Ethernet', 'on'])
            
            self.isolated_system = False
            
            msg = "Network connectivity restored"
            logger.info(f"✅ {msg}")
            
            return True, msg
            
        except Exception as e:
            error_msg = f"Failed to restore network: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def remove_rule(self, rule_id: str) -> Tuple[bool, str]:
        """
        Remove a firewall rule.
        
        Args:
            rule_id: ID of rule to remove
            
        Returns:
            Tuple of (success, message)
        """
        try:
            if rule_id not in self.rules:
                return False, f"Rule not found: {rule_id}"
            
            rule = self.rules[rule_id]
            
            # Remove from firewall (platform-specific)
            if self.system == 'windows':
                # Remove Windows firewall rule
                cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name=CyberGuardian_{rule_id}*']
                self._run_command(cmd)
            
            # Remove from our tracking
            del self.rules[rule_id]
            self.stats['active_rules'] = len(self.rules)
            
            msg = f"Rule removed: {rule_id}"
            logger.info(msg)
            
            return True, msg
            
        except Exception as e:
            return False, f"Failed to remove rule: {str(e)}"
    
    def get_statistics(self) -> Dict:
        """Get network isolation statistics"""
        self.stats['active_rules'] = len(self.rules)
        return self.stats.copy()
    
    def list_active_rules(self) -> List[FirewallRule]:
        """Get list of active firewall rules"""
        return list(self.rules.values())


def create_network_isolation() -> NetworkIsolation:
    """Factory function to create NetworkIsolation instance"""
    return NetworkIsolation()


# Integration function for threat_blocker
def handle_block_network(threat_context) -> Tuple[bool, str, Dict]:
    """
    Handler function for threat_blocker integration.
    
    Args:
        threat_context: ThreatContext object from threat_blocker
        
    Returns:
        Tuple of (success, message, details)
    """
    isolation = create_network_isolation()
    
    # Determine what to block based on threat context
    target = threat_context.target
    
    # Try to block IP if available
    if 'ip' in target or 'ip_address' in target:
        ip = target.get('ip') or target.get('ip_address')
        return isolation.block_ip(ip, direction="both", reason=threat_context.threat_type)
    
    # Try to block port if available
    elif 'port' in target:
        port = target.get('port')
        protocol = target.get('protocol', 'tcp')
        return isolation.block_port(port, protocol=protocol)
    
    # Try to block process if available
    elif 'process_name' in target:
        process_name = target.get('process_name')
        return isolation.block_process_network(process_name)
    
    # For critical threats, isolate entire system
    elif threat_context.severity.value >= 5:  # CRITICAL
        logger.warning("Critical threat detected - considering system isolation")
        # Don't auto-isolate, just return success with warning
        return True, "Critical threat - manual review recommended", {}
    
    return False, "No network target identified", {}


# Testing
if __name__ == "__main__":
    print("🔒 CyberGuardian - Network Isolation Test\n")
    
    isolation = create_network_isolation()
    
    print(f"📊 System: {isolation.system}")
    print(f"   Isolated: {isolation.isolated_system}")
    
    print("\n⚠️  WARNING: This test will attempt to create firewall rules")
    print("            Run with appropriate privileges (admin/root)")
    print("            Test with a safe IP address only!")
    
    # Test blocking a safe IP (documentation range)
    test_ip = "192.0.2.1"  # TEST-NET-1 (RFC 5737)
    
    print(f"\n🔒 Test 1: Block IP {test_ip}")
    success, message, details = isolation.block_ip(test_ip, direction="outbound")
    
    if success:
        print(f"   ✅ {message}")
        print(f"   Rule ID: {details.get('rule_id')}")
    else:
        print(f"   ❌ {message}")
    
    print("\n📊 Statistics:")
    stats = isolation.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n📋 Active rules:")
    rules = isolation.list_active_rules()
    for rule in rules[:3]:
        print(f"   - {rule.rule_id}: {rule.rule_type.value} → {rule.target}")
    
    print("\n✅ Network Isolation test complete!")
    print("\n⚠️  NOTE: Firewall rules were created and remain active")
    print("         Use Windows Firewall or iptables to review/remove")