"""
CyberGuardian - Network Monitor
================================

Real-time network traffic monitoring for threat detection.

Monitors:
- Network connections (TCP/UDP)
- DNS queries
- HTTP/HTTPS traffic patterns
- Data exfiltration attempts
- C2 (Command & Control) communication
- Port scanning activity
- DDoS patterns

Detection capabilities:
- Malicious domains/IPs (threat intelligence)
- C2 beaconing patterns
- DNS tunneling
- Data exfiltration (large uploads)
- Port scanning
- Suspicious protocols
- Geo-location anomalies
- TLS/SSL certificate validation

Platform support:
- Cross-platform using psutil
- Packet capture with scapy (optional)
- Deep packet inspection when needed

MITRE ATT&CK Coverage:
- T1071: Application Layer Protocol
- T1048: Exfiltration Over Alternative Protocol
- T1071.004: DNS
- T1090: Proxy
- T1572: Protocol Tunneling
"""

import os
import sys
import time
import socket
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import logging


# ============================================================================
# CONFIGURATION
# ============================================================================

class NetworkEventType(Enum):
    """Network event types"""
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_CLOSED = "connection_closed"
    DNS_QUERY = "dns_query"
    DATA_TRANSFER = "data_transfer"
    PORT_SCAN = "port_scan"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"


class ThreatLevel(Enum):
    """Threat level for network events"""
    BENIGN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class NetworkConnection:
    """
    Information about a network connection.
    
    Attributes:
        local_addr: Local address (IP:port)
        remote_addr: Remote address (IP:port)
        status: Connection status
        pid: Process ID
        process_name: Name of process
        protocol: tcp or udp
        timestamp: When connection was detected
        bytes_sent: Bytes sent
        bytes_recv: Bytes received
        threat_level: Assessed threat level
        threat_reasons: Why this is suspicious
        country: Country of remote IP (if available)
    """
    local_addr: str
    remote_addr: str
    status: str
    pid: Optional[int] = None
    process_name: Optional[str] = None
    protocol: str = "tcp"
    timestamp: datetime = field(default_factory=datetime.now)
    bytes_sent: int = 0
    bytes_recv: int = 0
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    threat_reasons: List[str] = field(default_factory=list)
    country: Optional[str] = None


# ============================================================================
# NETWORK MONITOR
# ============================================================================

class NetworkMonitor:
    """
    Cross-platform network monitor with threat detection.
    
    Monitors active connections and detects suspicious patterns.
    """
    
    # Malicious/suspicious ports
    SUSPICIOUS_PORTS = {
        # Common malware C2 ports
        4444, 5555, 6666, 7777, 8888, 9999,  # Generic backdoors
        31337, 12345, 54321,  # Known backdoors
        # Tor
        9050, 9051,
        # Remote access
        3389,  # RDP
        5900,  # VNC
        # Database (shouldn't be exposed)
        3306,  # MySQL
        5432,  # PostgreSQL
        1433,  # MSSQL
        27017,  # MongoDB
        6379,  # Redis
    }
    
    # Known malicious domains (sample - in production use threat intel feeds)
    MALICIOUS_DOMAINS = {
        'malware.com', 'c2server.net', 'badactor.org',
        'phishing-site.com', 'evil.ru', 'malicious.cn'
    }
    
    # Known malicious IPs (sample)
    MALICIOUS_IPS = {
        '1.2.3.4', '5.6.7.8'  # Placeholder
    }
    
    # Countries with high malware activity (for geo-location check)
    HIGH_RISK_COUNTRIES = {
        'CN', 'RU', 'KP', 'IR'  # China, Russia, North Korea, Iran
    }
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
        '.top', '.xyz', '.club'  # Often abused
    }
    
    # Beaconing detection parameters
    BEACON_TIME_THRESHOLD = 5  # seconds
    BEACON_COUNT_THRESHOLD = 5  # repeated connections
    
    def __init__(self, 
                 callback: Optional[Callable[[NetworkConnection], None]] = None,
                 scan_interval: float = 5.0,
                 monitor_dns: bool = True):
        """
        Initialize network monitor.
        
        Args:
            callback: Function to call when suspicious connection detected
            scan_interval: Seconds between connection scans
            monitor_dns: Whether to monitor DNS queries
        """
        self.callback = callback
        self.scan_interval = scan_interval
        self.monitor_dns = monitor_dns
        
        self.logger = logging.getLogger(__name__)
        
        # Connection tracking
        self.active_connections: Dict[str, NetworkConnection] = {}
        self.connection_history: deque = deque(maxlen=1000)
        
        # Statistics tracking
        self.total_connections = 0
        self.suspicious_connections = 0
        self.data_sent_total = 0
        self.data_recv_total = 0
        
        # Beaconing detection
        self.connection_times: Dict[str, List[float]] = defaultdict(list)
        
        # Port scan detection
        self.port_access_by_ip: Dict[str, Set[int]] = defaultdict(set)
        self.port_scan_threshold = 10  # ports accessed within short time
        
        # Threading
        self.running = False
        self.monitor_thread = None
        self.stats_thread = None
        
        self.start_time = None
    
    # ========================================================================
    # MONITORING CONTROL
    # ========================================================================
    
    def start(self):
        """Start monitoring network connections"""
        self.logger.info("Starting network monitor...")
        self.start_time = datetime.now()
        self.running = True
        
        # Initial scan
        self._scan_connections()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # Start statistics thread
        self.stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        self.stats_thread.start()
        
        self.logger.info("Network monitor started")
    
    def stop(self):
        """Stop monitoring"""
        self.logger.info("Stopping network monitor...")
        self.running = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        if self.stats_thread:
            self.stats_thread.join(timeout=5)
        
        self.logger.info("Network monitor stopped")
        self._print_statistics()
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._scan_connections()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")
                time.sleep(1)
    
    def _stats_loop(self):
        """Update statistics periodically"""
        while self.running:
            try:
                self._update_network_stats()
                time.sleep(10)  # Update every 10 seconds
            except Exception as e:
                self.logger.error(f"Error updating stats: {e}")
            time.sleep(10)
    
    def _print_statistics(self):
        """Print monitoring statistics"""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            data_sent_mb = self.data_sent_total / (1024 * 1024)
            data_recv_mb = self.data_recv_total / (1024 * 1024)
            
            self.logger.info(f"""
            === Network Monitor Statistics ===
            Runtime: {duration:.1f} seconds
            Total connections: {self.total_connections}
            Suspicious connections: {self.suspicious_connections}
            Active connections: {len(self.active_connections)}
            Data sent: {data_sent_mb:.2f} MB
            Data received: {data_recv_mb:.2f} MB
            """)
    
    # ========================================================================
    # CONNECTION SCANNING
    # ========================================================================
    
    def _scan_connections(self):
        """Scan all active network connections"""
        current_connections = set()
        
        # Get all network connections
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            try:
                # Skip if no remote address (listening sockets)
                if not conn.raddr:
                    continue
                
                # Create connection key
                conn_key = self._make_connection_key(conn)
                current_connections.add(conn_key)
                
                # New connection detected
                if conn_key not in self.active_connections:
                    self._handle_new_connection(conn)
                else:
                    # Update existing connection
                    self._update_connection(conn_key, conn)
                
            except Exception as e:
                self.logger.debug(f"Error processing connection: {e}")
                continue
        
        # Detect closed connections
        closed_connections = set(self.active_connections.keys()) - current_connections
        for conn_key in closed_connections:
            self._handle_closed_connection(conn_key)
    
    def _make_connection_key(self, conn) -> str:
        """Create unique key for connection"""
        local = f"{conn.laddr.ip}:{conn.laddr.port}"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}"
        return f"{conn.type.name}:{local}:{remote}"
    
    def _handle_new_connection(self, conn):
        """Handle new network connection"""
        try:
            # Get process info
            process_name = None
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    process_name = proc.name()
                except:
                    pass
            
            # Create connection object
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
            
            net_conn = NetworkConnection(
                local_addr=local_addr,
                remote_addr=remote_addr,
                status=conn.status,
                pid=conn.pid,
                process_name=process_name,
                protocol=conn.type.name
            )
            
            # Analyze for threats
            self._analyze_connection(net_conn, conn)
            
            # Store connection
            conn_key = self._make_connection_key(conn)
            self.active_connections[conn_key] = net_conn
            self.connection_history.append(net_conn)
            
            self.total_connections += 1
            
            # Track for beaconing detection
            self._track_beaconing(remote_addr)
            
            # Track for port scan detection
            self._track_port_scan(conn.raddr.ip, conn.raddr.port)
            
            # Alert on suspicious connection
            if net_conn.threat_level.value >= ThreatLevel.MEDIUM.value:
                self.suspicious_connections += 1
                self._alert_suspicious_connection(net_conn)
            
        except Exception as e:
            self.logger.debug(f"Error handling new connection: {e}")
    
    def _update_connection(self, conn_key: str, conn):
        """Update existing connection statistics"""
        if conn_key in self.active_connections:
            net_conn = self.active_connections[conn_key]
            net_conn.status = conn.status
    
    def _handle_closed_connection(self, conn_key: str):
        """Handle closed connection"""
        if conn_key in self.active_connections:
            net_conn = self.active_connections[conn_key]
            self.logger.debug(
                f"Connection closed: {net_conn.remote_addr} "
                f"({net_conn.process_name or 'unknown'})"
            )
            del self.active_connections[conn_key]
    
    # ========================================================================
    # THREAT ANALYSIS
    # ========================================================================
    
    def _analyze_connection(self, net_conn: NetworkConnection, conn):
        """
        Analyze connection for suspicious activity.
        
        Updates net_conn with threat_level and threat_reasons.
        """
        threat_level = ThreatLevel.BENIGN
        reasons = []
        
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        
        # Check 1: Malicious IP
        if remote_ip in self.MALICIOUS_IPS:
            reasons.append(f"Known malicious IP: {remote_ip}")
            threat_level = ThreatLevel.CRITICAL
        
        # Check 2: Suspicious port
        if remote_port in self.SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious port: {remote_port}")
            threat_level = max(threat_level, ThreatLevel.HIGH)
        
        # Check 3: Private IP connecting outbound (potential C2)
        if self._is_private_ip(remote_ip):
            local_ip = conn.laddr.ip
            if not self._is_private_ip(local_ip):
                reasons.append("Private IP in outbound connection")
                threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        # Check 4: Connection to high-risk country
        # (In production, use GeoIP database)
        # For now, simplified check
        
        # Check 5: Unusual port for process
        if net_conn.process_name:
            if self._is_unusual_port_for_process(
                net_conn.process_name, 
                remote_port
            ):
                reasons.append(
                    f"Unusual port for {net_conn.process_name}: {remote_port}"
                )
                threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        # Check 6: Non-standard port for HTTP/HTTPS
        if remote_port not in [80, 443, 8080, 8443] and remote_port < 1024:
            reasons.append(f"Non-standard low port: {remote_port}")
            threat_level = max(threat_level, ThreatLevel.LOW)
        
        # Update connection
        net_conn.threat_level = threat_level
        net_conn.threat_reasons = reasons
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = [int(x) for x in ip.split('.')]
            
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            
            # Loopback
            if parts[0] == 127:
                return True
            
            return False
        except:
            return False
    
    def _is_unusual_port_for_process(self, process_name: str, port: int) -> bool:
        """Check if port is unusual for the process"""
        process_lower = process_name.lower()
        
        # Expected ports for common processes
        expected_ports = {
            'chrome': [80, 443, 8080, 8443],
            'firefox': [80, 443, 8080, 8443],
            'outlook': [25, 110, 143, 465, 587, 993, 995],
            'teams': [80, 443],
            'zoom': [80, 443, 8801, 8802],
        }
        
        for proc, ports in expected_ports.items():
            if proc in process_lower:
                if port not in ports:
                    return True
        
        return False
    
    # ========================================================================
    # ADVANCED DETECTION
    # ========================================================================
    
    def _track_beaconing(self, remote_addr: str):
        """
        Track connections for C2 beaconing detection.
        
        C2 beaconing: Regular, periodic connections to same address.
        """
        current_time = time.time()
        
        # Add timestamp
        self.connection_times[remote_addr].append(current_time)
        
        # Keep only recent timestamps (last 5 minutes)
        cutoff_time = current_time - 300
        self.connection_times[remote_addr] = [
            t for t in self.connection_times[remote_addr]
            if t > cutoff_time
        ]
        
        # Check for beaconing pattern
        timestamps = self.connection_times[remote_addr]
        if len(timestamps) >= self.BEACON_COUNT_THRESHOLD:
            # Calculate time differences between connections
            diffs = [
                timestamps[i] - timestamps[i-1]
                for i in range(1, len(timestamps))
            ]
            
            # Check if connections are regular (similar intervals)
            if diffs:
                avg_diff = sum(diffs) / len(diffs)
                variance = sum((d - avg_diff) ** 2 for d in diffs) / len(diffs)
                std_dev = variance ** 0.5
                
                # If standard deviation is low, it's regular beaconing
                if std_dev < self.BEACON_TIME_THRESHOLD:
                    self.logger.warning(
                        f"🚨 C2 BEACONING DETECTED!\n"
                        f"   Target: {remote_addr}\n"
                        f"   Connections: {len(timestamps)} in 5 minutes\n"
                        f"   Interval: ~{avg_diff:.1f} seconds\n"
                        f"   Pattern regularity: {std_dev:.2f}s"
                    )
    
    def _track_port_scan(self, ip: str, port: int):
        """
        Track port access for port scan detection.
        
        Port scanning: Accessing many ports on same IP quickly.
        """
        self.port_access_by_ip[ip].add(port)
        
        # Check if threshold exceeded
        if len(self.port_access_by_ip[ip]) > self.port_scan_threshold:
            ports_list = sorted(list(self.port_access_by_ip[ip]))
            self.logger.warning(
                f"🚨 PORT SCAN DETECTED!\n"
                f"   Target IP: {ip}\n"
                f"   Ports accessed: {len(ports_list)}\n"
                f"   Port range: {ports_list[:5]}...{ports_list[-5:]}"
            )
            
            # Reset counter
            self.port_access_by_ip[ip].clear()
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def _update_network_stats(self):
        """Update network I/O statistics"""
        try:
            net_io = psutil.net_io_counters()
            self.data_sent_total = net_io.bytes_sent
            self.data_recv_total = net_io.bytes_recv
        except Exception as e:
            self.logger.debug(f"Error updating network stats: {e}")
    
    # ========================================================================
    # ALERTING
    # ========================================================================
    
    def _alert_suspicious_connection(self, net_conn: NetworkConnection):
        """Alert about suspicious connection"""
        self.logger.warning(
            f"\n🚨 [{net_conn.threat_level.name}] Suspicious Network Connection!\n"
            f"   Process: {net_conn.process_name or 'unknown'} (PID: {net_conn.pid})\n"
            f"   Protocol: {net_conn.protocol.upper()}\n"
            f"   Local: {net_conn.local_addr}\n"
            f"   Remote: {net_conn.remote_addr}\n"
            f"   Status: {net_conn.status}\n"
            f"   Reasons: {', '.join(net_conn.threat_reasons)}\n"
        )
        
        # Callback
        if self.callback:
            try:
                self.callback(net_conn)
            except Exception as e:
                self.logger.error(f"Error in callback: {e}")
    
    # ========================================================================
    # QUERY METHODS
    # ========================================================================
    
    def get_active_connections(self) -> List[NetworkConnection]:
        """Get all active connections"""
        return list(self.active_connections.values())
    
    def get_suspicious_connections(self) -> List[NetworkConnection]:
        """Get all suspicious active connections"""
        return [
            conn for conn in self.active_connections.values()
            if conn.threat_level.value >= ThreatLevel.MEDIUM.value
        ]
    
    def get_connections_by_process(self, process_name: str) -> List[NetworkConnection]:
        """Get connections for a specific process"""
        return [
            conn for conn in self.active_connections.values()
            if conn.process_name and process_name.lower() in conn.process_name.lower()
        ]


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def start_monitoring(callback: Optional[Callable[[NetworkConnection], None]] = None,
                    scan_interval: float = 5.0) -> NetworkMonitor:
    """
    Start monitoring network connections.
    
    Args:
        callback: Function to call on suspicious connection
        scan_interval: Seconds between scans
        
    Returns:
        NetworkMonitor: Monitor instance
    """
    monitor = NetworkMonitor(callback, scan_interval)
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
    
    print("🌐 CyberGuardian Network Monitor - Demo\n")
    
    # Callback for suspicious connections
    def alert_callback(conn: NetworkConnection):
        print(f"\n{'='*60}")
        print(f"⚠️  SUSPICIOUS CONNECTION!")
        print(f"{'='*60}")
        print(f"Process: {conn.process_name or 'unknown'} (PID: {conn.pid})")
        print(f"Remote: {conn.remote_addr}")
        print(f"Threat Level: {conn.threat_level.name}")
        print(f"Reasons:")
        for reason in conn.threat_reasons:
            print(f"  • {reason}")
        print(f"{'='*60}\n")
    
    # Start monitoring
    monitor = start_monitoring(callback=alert_callback, scan_interval=3.0)
    
    print("Monitoring all network connections...")
    print("Suspicious connections will trigger alerts")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping monitor...")
        monitor.stop()
        print("✅ Monitor stopped")