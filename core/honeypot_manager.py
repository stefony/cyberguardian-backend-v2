"""
CyberGuardian AI - Honeypot Manager
Real honeypot system for capturing attacks
"""

import socket
import threading
import logging
import time
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class AttackLog:
    """Attack log entry"""
    timestamp: str
    honeypot_type: str
    source_ip: str
    source_port: int
    attack_type: str
    payload: str
    country: Optional[str] = None
    city: Optional[str] = None

class HoneypotBase:
    """Base class for honeypots"""
    
    def __init__(self, name: str, port: int, honeypot_type: str):
        self.name = name
        self.port = port
        self.honeypot_type = honeypot_type
        self.running = False
        self.thread = None
        self.socket = None
        self.attack_logs: List[AttackLog] = []
        
    def start(self):
        """Start honeypot"""
        if self.running:
            logger.warning(f"{self.name} already running")
            return False
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info(f"{self.name} started on port {self.port}")
        return True
    
    def stop(self):
        """Stop honeypot"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        logger.info(f"{self.name} stopped")
    
    def _run(self):
        """Run honeypot (override in subclass)"""
        raise NotImplementedError
    
    def log_attack(self, source_ip: str, source_port: int, attack_type: str, payload: str):
        """Log attack"""
        # Get geolocation
        country, city = self._get_geolocation(source_ip)
        
        attack = AttackLog(
            timestamp=datetime.now().isoformat(),
            honeypot_type=self.honeypot_type,
            source_ip=source_ip,
            source_port=source_port,
            attack_type=attack_type,
            payload=payload[:500],  # Limit payload size
            country=country,
            city=city
        )
        
        self.attack_logs.append(attack)
        
        # Log to database
        self._save_to_db(attack)
        
        logger.info(f"Attack logged: {attack_type} from {source_ip}:{source_port}")
    
    def _get_geolocation(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Get IP geolocation (using free API)"""
        # Skip private IPs
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'):
            return "Local", "Local"
        
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
            if response.status_code == 200:
                data = response.json()
                return data.get('country'), data.get('city')
        except Exception as e:
            logger.error(f"Geolocation failed: {e}")
        
        return None, None
    
    def _save_to_db(self, attack: AttackLog):
        """Save attack to database"""
        try:
            db_path = Path(__file__).parent.parent / 'database' / 'cyberguardian.db'
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO honeypot_logs (
                    honeypot_id, timestamp, source_ip, source_port,
                    request_type, payload, blocked
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                1,  # Default honeypot_id
                attack.timestamp,
                attack.source_ip,
                attack.source_port,
                attack.attack_type,
                attack.payload,
                1  # Always blocked
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to save attack to DB: {e}")

class SSHHoneypot(HoneypotBase):
    """SSH Honeypot - captures SSH login attempts"""
    
    def __init__(self, port: int = 2222):
        super().__init__("SSH Honeypot", port, "ssh")
        self.failed_logins = 0
    
    def _run(self):
        """Run SSH honeypot"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.socket.settimeout(1.0)
            
            logger.info(f"SSH Honeypot listening on port {self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    threading.Thread(
                        target=self._handle_ssh_client,
                        args=(client_socket, address),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"SSH accept error: {e}")
        
        except Exception as e:
            logger.error(f"SSH honeypot failed to start: {e}")
    
    def _handle_ssh_client(self, client_socket, address):
        """Handle SSH client connection"""
        try:
            source_ip, source_port = address
            
            # Send fake SSH banner
            banner = b"SSH-2.0-OpenSSH_7.9p1 Ubuntu-10\r\n"
            client_socket.send(banner)
            
            # Wait for client data (login attempt)
            client_socket.settimeout(5.0)
            data = client_socket.recv(1024)
            
            if data:
                payload = data.decode('utf-8', errors='ignore')
                self.log_attack(
                    source_ip,
                    source_port,
                    "SSH Login Attempt",
                    payload
                )
                self.failed_logins += 1
            
            # Close connection
            client_socket.close()
        
        except Exception as e:
            logger.error(f"SSH client handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

class HTTPHoneypot(HoneypotBase):
    """HTTP Honeypot - captures HTTP requests"""
    
    def __init__(self, port: int = 8080):
        super().__init__("HTTP Honeypot", port, "http")
        self.total_requests = 0
    
    def _run(self):
        """Run HTTP honeypot"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.listen(5)
            self.socket.settimeout(1.0)
            
            logger.info(f"HTTP Honeypot listening on port {self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    threading.Thread(
                        target=self._handle_http_client,
                        args=(client_socket, address),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"HTTP accept error: {e}")
        
        except Exception as e:
            logger.error(f"HTTP honeypot failed to start: {e}")
    
    def _handle_http_client(self, client_socket, address):
        """Handle HTTP client connection"""
        try:
            source_ip, source_port = address
            
            # Receive HTTP request
            client_socket.settimeout(5.0)
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if request:
                self.total_requests += 1
                
                # Parse request type
                attack_type = "HTTP Request"
                if "POST" in request:
                    attack_type = "HTTP POST Attack"
                elif "sql" in request.lower() or "union" in request.lower():
                    attack_type = "SQL Injection Attempt"
                elif "<script>" in request.lower():
                    attack_type = "XSS Attempt"
                elif "../" in request or "..%2F" in request:
                    attack_type = "Directory Traversal"
                
                self.log_attack(source_ip, source_port, attack_type, request)
                
                # Send fake response
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n\r\n"
                    "<html><body><h1>Welcome</h1></body></html>"
                )
                client_socket.send(response.encode())
            
            client_socket.close()
        
        except Exception as e:
            logger.error(f"HTTP client handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

class HoneypotManager:
    """
    Honeypot Manager - manages multiple honeypots
    """
    
    def __init__(self):
        self.honeypots: Dict[str, HoneypotBase] = {}
        self.initialized = False
    
    def initialize(self):
        """Initialize honeypots"""
        if self.initialized:
            return
        
        try:
            # Create SSH honeypot on port 2222
            ssh_honeypot = SSHHoneypot(port=2222)
            self.honeypots['ssh'] = ssh_honeypot
            
            # Create HTTP honeypot on port 8080
            http_honeypot = HTTPHoneypot(port=8080)
            self.honeypots['http'] = http_honeypot
            
            self.initialized = True
            logger.info("Honeypot Manager initialized")
        
        except Exception as e:
            logger.error(f"Failed to initialize honeypots: {e}")
    
    def start_honeypot(self, honeypot_type: str) -> bool:
        """Start specific honeypot"""
        if honeypot_type not in self.honeypots:
            logger.error(f"Unknown honeypot type: {honeypot_type}")
            return False
        
        return self.honeypots[honeypot_type].start()
    
    def stop_honeypot(self, honeypot_type: str) -> bool:
        """Stop specific honeypot"""
        if honeypot_type not in self.honeypots:
            return False
        
        self.honeypots[honeypot_type].stop()
        return True
    
    def start_all(self):
        """Start all honeypots"""
        for name, honeypot in self.honeypots.items():
            honeypot.start()
    
    def stop_all(self):
        """Stop all honeypots"""
        for honeypot in self.honeypots.values():
            honeypot.stop()
    
    def get_status(self) -> Dict:
        """Get status of all honeypots"""
        status = {}
        for name, honeypot in self.honeypots.items():
            status[name] = {
                'name': honeypot.name,
                'type': honeypot.honeypot_type,
                'port': honeypot.port,
                'running': honeypot.running,
                'attacks_logged': len(honeypot.attack_logs)
            }
        return status
    
    def get_recent_attacks(self, limit: int = 50) -> List[Dict]:
        """Get recent attacks from all honeypots"""
        all_attacks = []
        
        for honeypot in self.honeypots.values():
            for attack in honeypot.attack_logs[-limit:]:
                all_attacks.append({
                    'timestamp': attack.timestamp,
                    'honeypot_type': attack.honeypot_type,
                    'source_ip': attack.source_ip,
                    'source_port': attack.source_port,
                    'attack_type': attack.attack_type,
                    'payload': attack.payload,
                    'country': attack.country,
                    'city': attack.city
                })
        
        # Sort by timestamp (newest first)
        all_attacks.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return all_attacks[:limit]
    
    def get_statistics(self) -> Dict:
        """Get honeypot statistics"""
        total_attacks = sum(len(hp.attack_logs) for hp in self.honeypots.values())
        
        attack_types = {}
        countries = {}
        
        for honeypot in self.honeypots.values():
            for attack in honeypot.attack_logs:
                # Count attack types
                attack_types[attack.attack_type] = attack_types.get(attack.attack_type, 0) + 1
                
                # Count countries
                if attack.country:
                    countries[attack.country] = countries.get(attack.country, 0) + 1
        
        return {
            'total_attacks': total_attacks,
            'attack_types': attack_types,
            'top_countries': dict(sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]),
            'active_honeypots': sum(1 for hp in self.honeypots.values() if hp.running)
        }


# Global instance
_manager = None

def get_honeypot_manager() -> HoneypotManager:
    """Get global honeypot manager instance"""
    global _manager
    if _manager is None:
        _manager = HoneypotManager()
        _manager.initialize()
    return _manager


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("🍯 Testing Honeypot Manager...")
    
    manager = get_honeypot_manager()
    
    # Start all honeypots
    print("\n🚀 Starting honeypots...")
    manager.start_all()
    
    print("\n📊 Status:")
    status = manager.get_status()
    for name, info in status.items():
        print(f"  {info['name']}: {'🟢 Running' if info['running'] else '🔴 Stopped'} on port {info['port']}")
    
    print("\n⏳ Waiting 30 seconds for attacks...")
    print("   Try: telnet localhost 2222 (SSH)")
    print("   Try: curl http://localhost:8080 (HTTP)")
    
    time.sleep(30)
    
    # Show statistics
    print("\n📈 Statistics:")
    stats = manager.get_statistics()
    print(f"  Total Attacks: {stats['total_attacks']}")
    print(f"  Active Honeypots: {stats['active_honeypots']}")
    
    if stats['attack_types']:
        print("\n  Attack Types:")
        for attack_type, count in stats['attack_types'].items():
            print(f"    - {attack_type}: {count}")
    
    # Show recent attacks
    print("\n🎯 Recent Attacks:")
    attacks = manager.get_recent_attacks(limit=10)
    for i, attack in enumerate(attacks, 1):
        print(f"  {i}. {attack['attack_type']} from {attack['source_ip']} ({attack['country'] or 'Unknown'})")
    
    # Stop all
    print("\n🛑 Stopping honeypots...")
    manager.stop_all()
    
    print("\n✅ Test complete!")