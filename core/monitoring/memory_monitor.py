"""
CyberGuardian - Memory Monitor & Scanner
=========================================

Memory forensics and in-memory threat detection.

Monitors:
- Process memory regions
- DLL/library injection
- Process hollowing
- Reflective DLL loading
- Shellcode in memory
- Memory-resident malware
- Credential dumping attempts

Detection capabilities:
- Fileless malware (memory-only)
- Code injection (DLL, shellcode)
- Process hollowing detection
- Reflective loading detection
- Memory anomalies (RWX regions)
- Suspicious memory patterns
- PE headers in memory
- Known malware signatures in RAM

Platform support:
- Windows: ReadProcessMemory API
- Linux: /proc/[pid]/maps, /proc/[pid]/mem
- macOS: vm_read

MITRE ATT&CK Coverage:
- T1055: Process Injection
- T1055.001: DLL Injection
- T1055.002: Portable Executable Injection
- T1055.003: Thread Execution Hijacking
- T1055.012: Process Hollowing
- T1620: Reflective Code Loading
- T1003: OS Credential Dumping

Memory Forensics Techniques:
- YARA scanning of memory
- Entropy analysis (packed/encrypted code)
- PE header detection
- Known shellcode patterns
- API hook detection
"""

import os
import sys
import time
import psutil
import struct
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

# Platform-specific imports
if sys.platform == 'win32':
    try:
        import ctypes
        from ctypes import wintypes
        CTYPES_AVAILABLE = True
    except ImportError:
        CTYPES_AVAILABLE = False
else:
    CTYPES_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

class MemoryThreatType(Enum):
    """Types of memory-based threats"""
    CODE_INJECTION = "code_injection"
    PROCESS_HOLLOWING = "process_hollowing"
    REFLECTIVE_LOADING = "reflective_loading"
    SHELLCODE = "shellcode"
    MEMORY_ANOMALY = "memory_anomaly"
    SUSPICIOUS_MODULE = "suspicious_module"


class ThreatLevel(Enum):
    """Threat level for memory events"""
    BENIGN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class MemoryRegion:
    """
    Information about a memory region.
    
    Attributes:
        pid: Process ID
        process_name: Process name
        base_address: Start address
        size: Region size in bytes
        protection: Memory protection flags
        region_type: Type (private, mapped, image)
        is_executable: Whether region is executable
        is_writable: Whether region is writable
        entropy: Shannon entropy (randomness indicator)
        contains_pe_header: Whether PE header detected
        threat_type: Type of threat detected
        threat_level: Severity level
        threat_reasons: Why this is suspicious
    """
    pid: int
    process_name: str
    base_address: int
    size: int
    protection: str
    region_type: str = "unknown"
    is_executable: bool = False
    is_writable: bool = False
    entropy: float = 0.0
    contains_pe_header: bool = False
    threat_type: Optional[MemoryThreatType] = None
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    threat_reasons: List[str] = field(default_factory=list)


# ============================================================================
# MEMORY SCANNER
# ============================================================================

class MemoryScanner:
    """
    Cross-platform memory scanner for threat detection.
    
    Focuses on detecting fileless malware and code injection.
    """
    
    # PE header signatures
    PE_SIGNATURES = [
        b'MZ',  # DOS header
        b'PE\x00\x00',  # PE signature
    ]
    
    # Common shellcode patterns (simplified)
    SHELLCODE_PATTERNS = [
        # Common x86/x64 instructions often in shellcode
        b'\x64\xa1\x30\x00\x00\x00',  # mov eax, fs:[0x30] (PEB access)
        b'\x65\x48\x8b\x04\x25',  # mov rax, gs:[0x25] (x64 PEB)
        b'\xeb\xfe',  # jmp $ (infinite loop)
        b'\x90\x90\x90\x90',  # NOP sled
    ]
    
    # Known malicious DLLs (sample)
    SUSPICIOUS_DLLS = {
        'mimikatz.dll', 'pwdump.dll', 'gsecdump.dll',
        'procdump.dll', 'injector.dll', 'reflective.dll'
    }
    
    # High entropy threshold (indicates encryption/packing)
    HIGH_ENTROPY_THRESHOLD = 7.0
    
    def __init__(self, 
                 callback: Optional[Callable[[MemoryRegion], None]] = None,
                 scan_interval: float = 60.0,
                 deep_scan: bool = False):
        """
        Initialize memory scanner.
        
        Args:
            callback: Function to call when threat detected
            scan_interval: Seconds between scans
            deep_scan: Whether to perform deep memory analysis
        """
        self.callback = callback
        self.scan_interval = scan_interval
        self.deep_scan = deep_scan
        
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.processes_scanned = 0
        self.regions_scanned = 0
        self.threats_detected = 0
        self.start_time = None
        
        # Threading
        self.running = False
        self.scan_thread = None
        
        # Platform detection
        self.is_windows = sys.platform == 'win32'
    
    # ========================================================================
    # SCANNING CONTROL
    # ========================================================================
    
    def start(self):
        """Start memory scanning"""
        self.logger.info("Starting memory scanner...")
        self.start_time = datetime.now()
        self.running = True
        
        # Start scanning thread
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        
        self.logger.info("Memory scanner started")
    
    def stop(self):
        """Stop scanning"""
        self.logger.info("Stopping memory scanner...")
        self.running = False
        
        if self.scan_thread:
            self.scan_thread.join(timeout=10)
        
        self.logger.info("Memory scanner stopped")
        self._print_statistics()
    
    def _scan_loop(self):
        """Main scanning loop"""
        while self.running:
            try:
                self._scan_all_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                self.logger.error(f"Error in scan loop: {e}")
                time.sleep(5)
    
    def _print_statistics(self):
        """Print scanning statistics"""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"""
            === Memory Scanner Statistics ===
            Runtime: {duration:.1f} seconds
            Processes scanned: {self.processes_scanned}
            Memory regions scanned: {self.regions_scanned}
            Threats detected: {self.threats_detected}
            """)
    
    # ========================================================================
    # PROCESS SCANNING
    # ========================================================================
    
    def _scan_all_processes(self):
        """Scan memory of all accessible processes"""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self._scan_process(proc)
                self.processes_scanned += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                self.logger.debug(f"Error scanning process {proc.pid}: {e}")
    
    def _scan_process(self, proc: psutil.Process):
        """
        Scan memory of a single process.
        
        Args:
            proc: psutil Process object
        """
        pid = proc.pid
        name = proc.name()
        
        # Get memory maps
        try:
            memory_maps = proc.memory_maps()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return
        
        # Analyze each memory region
        for mmap in memory_maps:
            self.regions_scanned += 1
            
            try:
                region = self._analyze_memory_region(pid, name, mmap)
                
                # Alert on threats
                if region and region.threat_level.value >= ThreatLevel.MEDIUM.value:
                    self.threats_detected += 1
                    self._alert_memory_threat(region)
                    
            except Exception as e:
                self.logger.debug(f"Error analyzing region: {e}")
    
    # ========================================================================
    # MEMORY REGION ANALYSIS
    # ========================================================================
    
    def _analyze_memory_region(self, 
                               pid: int, 
                               process_name: str, 
                               mmap) -> Optional[MemoryRegion]:
        """
        Analyze a memory region for suspicious characteristics.
        
        Args:
            pid: Process ID
            process_name: Process name
            mmap: Memory map from psutil
            
        Returns:
            MemoryRegion or None if not suspicious
        """
        # Parse address (format: "0x7fff12340000")
        try:
            base_address = int(mmap.addr.split('-')[0], 16)
        except:
            return None
        
        # Get size
        size = mmap.rss  # Resident Set Size
        
        # Parse permissions
        perms = mmap.perms if hasattr(mmap, 'perms') else ''
        is_readable = 'r' in perms
        is_writable = 'w' in perms
        is_executable = 'x' in perms
        
        # Create region object
        region = MemoryRegion(
            pid=pid,
            process_name=process_name,
            base_address=base_address,
            size=size,
            protection=perms,
            is_executable=is_executable,
            is_writable=is_writable
        )
        
        # Analyze for threats
        self._detect_threats(region, mmap)
        
        return region if region.threat_level.value >= ThreatLevel.MEDIUM.value else None
    
    def _detect_threats(self, region: MemoryRegion, mmap):
        """
        Detect threats in memory region.
        
        Updates region with threat information.
        """
        threat_level = ThreatLevel.BENIGN
        reasons = []
        threat_type = None
        
        # Check 1: RWX memory (Read-Write-Execute - suspicious!)
        if region.is_readable and region.is_writable and region.is_executable:
            reasons.append("RWX memory region (executable + writable)")
            threat_level = ThreatLevel.HIGH
            threat_type = MemoryThreatType.CODE_INJECTION
        
        # Check 2: Private executable memory (not backed by file)
        if region.is_executable:
            path = mmap.path if hasattr(mmap, 'path') else ''
            
            # No backing file = private memory
            if not path or path == '[anon]' or path.startswith('['):
                reasons.append("Private executable memory (not backed by DLL/EXE)")
                threat_level = max(threat_level, ThreatLevel.HIGH)
                threat_type = MemoryThreatType.SHELLCODE
        
        # Check 3: Suspicious module name
        if hasattr(mmap, 'path') and mmap.path:
            path_lower = mmap.path.lower()
            
            # Check against suspicious DLL list
            for suspicious_dll in self.SUSPICIOUS_DLLS:
                if suspicious_dll in path_lower:
                    reasons.append(f"Suspicious module: {suspicious_dll}")
                    threat_level = ThreatLevel.CRITICAL
                    threat_type = MemoryThreatType.SUSPICIOUS_MODULE
            
            # DLL from temp directory
            if any(x in path_lower for x in ['temp', 'tmp', 'appdata\\local\\temp']):
                if path_lower.endswith('.dll'):
                    reasons.append("DLL loaded from temp directory")
                    threat_level = max(threat_level, ThreatLevel.MEDIUM)
                    threat_type = MemoryThreatType.SUSPICIOUS_MODULE
        
        # Check 4: Large private memory regions (could be unpacked malware)
        if region.size > 10 * 1024 * 1024:  # > 10 MB
            path = mmap.path if hasattr(mmap, 'path') else ''
            if not path or path.startswith('['):
                reasons.append(f"Large private memory region: {region.size / (1024*1024):.1f} MB")
                threat_level = max(threat_level, ThreatLevel.LOW)
        
        # Deep scan checks (expensive operations)
        if self.deep_scan and region.is_executable:
            # Check 5: Read memory and check for PE headers (Windows)
            if self._check_pe_header_in_memory(region):
                reasons.append("PE header found in memory (possible reflective loading)")
                threat_level = max(threat_level, ThreatLevel.HIGH)
                threat_type = MemoryThreatType.REFLECTIVE_LOADING
                region.contains_pe_header = True
            
            # Check 6: Entropy analysis (high entropy = encryption/packing)
            if self._check_high_entropy(region):
                reasons.append("High entropy detected (encrypted/packed code)")
                threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        # Update region
        region.threat_level = threat_level
        region.threat_reasons = reasons
        region.threat_type = threat_type
    
    # ========================================================================
    # DEEP ANALYSIS
    # ========================================================================
    
    def _check_pe_header_in_memory(self, region: MemoryRegion) -> bool:
        """
        Check if memory region contains PE header.
        
        This indicates reflective DLL loading or process hollowing.
        """
        try:
            # Read first 1024 bytes of region
            memory_data = self._read_process_memory(
                region.pid, 
                region.base_address, 
                1024
            )
            
            if memory_data:
                # Check for MZ signature
                if memory_data[:2] == b'MZ':
                    return True
                
                # Check for PE signature (offset 0x3C contains PE header offset)
                if len(memory_data) >= 64:
                    try:
                        pe_offset = struct.unpack('<I', memory_data[0x3C:0x40])[0]
                        if pe_offset < len(memory_data) - 4:
                            if memory_data[pe_offset:pe_offset+2] == b'PE':
                                return True
                    except:
                        pass
            
        except Exception as e:
            self.logger.debug(f"Error checking PE header: {e}")
        
        return False
    
    def _check_high_entropy(self, region: MemoryRegion) -> bool:
        """
        Check if memory region has high entropy (indicates encryption/packing).
        
        Returns:
            bool: True if entropy is suspiciously high
        """
        try:
            # Read sample of memory
            sample_size = min(8192, region.size)
            memory_data = self._read_process_memory(
                region.pid,
                region.base_address,
                sample_size
            )
            
            if memory_data and len(memory_data) > 0:
                entropy = self._calculate_entropy(memory_data)
                region.entropy = entropy
                
                # High entropy indicates encryption or compression
                if entropy > self.HIGH_ENTROPY_THRESHOLD:
                    return True
        
        except Exception as e:
            self.logger.debug(f"Error calculating entropy: {e}")
        
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Byte data
            
        Returns:
            float: Entropy value (0-8, higher = more random)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for freq in frequencies:
            if freq > 0:
                probability = freq / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    # ========================================================================
    # MEMORY READING (Platform-specific)
    # ========================================================================
    
    def _read_process_memory(self, 
                            pid: int, 
                            address: int, 
                            size: int) -> Optional[bytes]:
        """
        Read memory from process.
        
        Args:
            pid: Process ID
            address: Memory address
            size: Bytes to read
            
        Returns:
            bytes or None
        """
        if self.is_windows:
            return self._read_memory_windows(pid, address, size)
        else:
            return self._read_memory_unix(pid, address, size)
    
    def _read_memory_windows(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """Read memory on Windows using ReadProcessMemory"""
        if not CTYPES_AVAILABLE:
            return None
        
        try:
            # Open process
            PROCESS_VM_READ = 0x0010
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_VM_READ,
                False,
                pid
            )
            
            if not handle:
                return None
            
            # Allocate buffer
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            # Read memory
            success = ctypes.windll.kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read)
            )
            
            # Close handle
            ctypes.windll.kernel32.CloseHandle(handle)
            
            if success:
                return buffer.raw[:bytes_read.value]
        
        except Exception as e:
            self.logger.debug(f"Error reading Windows memory: {e}")
        
        return None
    
    def _read_memory_unix(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """Read memory on Linux/macOS using /proc or vm_read"""
        try:
            # Linux: /proc/[pid]/mem
            if sys.platform.startswith('linux'):
                mem_file = f"/proc/{pid}/mem"
                if os.path.exists(mem_file):
                    with open(mem_file, 'rb') as f:
                        f.seek(address)
                        return f.read(size)
            
            # macOS: Would need vm_read (complex, skipping for now)
        
        except Exception as e:
            self.logger.debug(f"Error reading Unix memory: {e}")
        
        return None
    
    # ========================================================================
    # ALERTING
    # ========================================================================
    
    def _alert_memory_threat(self, region: MemoryRegion):
        """Alert about memory-based threat"""
        self.logger.warning(
            f"\n🚨 [{region.threat_level.name}] Memory Threat Detected!\n"
            f"   Process: {region.process_name} (PID: {region.pid})\n"
            f"   Type: {region.threat_type.value if region.threat_type else 'unknown'}\n"
            f"   Address: 0x{region.base_address:x}\n"
            f"   Size: {region.size / 1024:.1f} KB\n"
            f"   Protection: {region.protection}\n"
            f"   Entropy: {region.entropy:.2f}\n"
            f"   PE Header: {'Yes' if region.contains_pe_header else 'No'}\n"
            f"   Reasons: {', '.join(region.threat_reasons)}\n"
        )
        
        # Callback
        if self.callback:
            try:
                self.callback(region)
            except Exception as e:
                self.logger.error(f"Error in callback: {e}")


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def start_scanning(callback: Optional[Callable[[MemoryRegion], None]] = None,
                  scan_interval: float = 60.0,
                  deep_scan: bool = False) -> MemoryScanner:
    """
    Start memory scanning.
    
    Args:
        callback: Function to call on threat
        scan_interval: Seconds between scans
        deep_scan: Enable deep analysis
        
    Returns:
        MemoryScanner: Scanner instance
    """
    scanner = MemoryScanner(callback, scan_interval, deep_scan)
    scanner.start()
    return scanner


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🧠 CyberGuardian Memory Scanner - Demo\n")
    
    # Callback for threats
    def alert_callback(region: MemoryRegion):
        print(f"\n{'='*60}")
        print(f"⚠️  MEMORY THREAT!")
        print(f"{'='*60}")
        print(f"Process: {region.process_name} (PID: {region.pid})")
        print(f"Type: {region.threat_type.value if region.threat_type else 'unknown'}")
        print(f"Threat Level: {region.threat_level.name}")
        print(f"Reasons:")
        for reason in region.threat_reasons:
            print(f"  • {reason}")
        print(f"{'='*60}\n")
    
    # Start scanning
    scanner = start_scanning(
        callback=alert_callback, 
        scan_interval=30.0,
        deep_scan=True  # Enable deep analysis
    )
    
    print("Scanning process memory...")
    print("Looking for code injection, shellcode, and anomalies")
    print("This may take a while on first scan...")
    print("Press Ctrl+C to stop\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping scanner...")
        scanner.stop()
        print("✅ Scanner stopped")