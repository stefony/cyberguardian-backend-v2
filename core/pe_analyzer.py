"""
CyberGuardian AI - PE (Portable Executable) Analyzer
Windows executable heuristic analysis
"""

import pefile
import math
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class PEAnalysisResult:
    """PE analysis result"""
    file_path: str
    is_pe: bool
    is_dll: bool
    is_driver: bool
    is_packed: bool
    entropy: float
    suspicious_sections: List[str]
    suspicious_imports: List[str]
    suspicious_strings: List[str]
    has_overlay: bool
    threat_score: float
    indicators: List[str]

class PEAnalyzer:
    """
    PE File Heuristic Analyzer
    
    Analyzes Windows executables for suspicious characteristics:
    - File entropy (packed/encrypted detection)
    - Suspicious imports (malware APIs)
    - Section analysis (unusual sections)
    - Overlay detection
    - Anti-debug/anti-VM indicators
    """
    
    # Suspicious API imports commonly used by malware
    SUSPICIOUS_IMPORTS = [
        # Process manipulation
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'OpenProcess', 'TerminateProcess', 'NtUnmapViewOfSection',
        
        # Code injection
        'LoadLibrary', 'GetProcAddress', 'VirtualAlloc', 'VirtualProtect',
        
        # Keylogging
        'GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx',
        
        # Anti-debug
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 
        'NtQueryInformationProcess', 'OutputDebugString',
        
        # Network
        'InternetOpen', 'InternetConnect', 'HttpSendRequest',
        'WSAStartup', 'socket', 'connect', 'send', 'recv',
        
        # Registry
        'RegSetValue', 'RegCreateKey', 'RegOpenKey',
        
        # Crypto
        'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext'
    ]
    
    # Suspicious section names
    SUSPICIOUS_SECTIONS = [
        '.upx', '.aspack', '.adata', '.petite', '.packed',
        '.nsp', '.boom', '.jiagu', '.themida'
    ]
    
    def __init__(self):
        """Initialize PE analyzer"""
        self.analyzed_files = 0
        self.threats_detected = 0
    
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        High entropy (>7.0) indicates packing/encryption
        
        Args:
            data: Bytes to analyze
            
        Returns:
            Entropy value (0.0 - 8.0)
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
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_file(self, file_path: str) -> Optional[PEAnalysisResult]:
        """
        Analyze PE file for suspicious characteristics
        
        Args:
            file_path: Path to PE file
            
        Returns:
            PEAnalysisResult or None if not a PE file
        """
        try:
            pe = pefile.PE(file_path)
            self.analyzed_files += 1
            
            indicators = []
            threat_score = 0.0
            
            # Basic file type detection
            is_dll = pe.is_dll()
            is_driver = pe.is_driver()
            is_exe = pe.is_exe()
            
            # Calculate file entropy
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_entropy = self.calculate_entropy(file_data)
            
            # Check for packing (high entropy)
            is_packed = file_entropy > 7.0
            if is_packed:
                threat_score += 20
                indicators.append(f"High entropy ({file_entropy:.2f}) - likely packed/encrypted")
            
            # Analyze sections
            suspicious_sections = []
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                # Check for suspicious section names
                if any(susp in section_name.lower() for susp in self.SUSPICIOUS_SECTIONS):
                    suspicious_sections.append(section_name)
                    threat_score += 15
                    indicators.append(f"Suspicious section: {section_name}")
                
                # Check section entropy
                section_data = section.get_data()
                section_entropy = self.calculate_entropy(section_data)
                
                if section_entropy > 7.5:
                    threat_score += 10
                    indicators.append(f"High entropy in section {section_name} ({section_entropy:.2f})")
                
                # Check for executable + writable sections (unusual)
                if (section.Characteristics & 0x20000000 and  # Executable
                    section.Characteristics & 0x80000000):   # Writable
                    threat_score += 15
                    indicators.append(f"Writable + executable section: {section_name}")
            
            # Analyze imports
            suspicious_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            
                            if func_name in self.SUSPICIOUS_IMPORTS:
                                suspicious_imports.append(f"{dll_name}!{func_name}")
                
                # Score based on number of suspicious imports
                if len(suspicious_imports) > 10:
                    threat_score += 30
                    indicators.append(f"Many suspicious imports ({len(suspicious_imports)})")
                elif len(suspicious_imports) > 5:
                    threat_score += 20
                    indicators.append(f"Multiple suspicious imports ({len(suspicious_imports)})")
                elif len(suspicious_imports) > 0:
                    threat_score += 10
                    indicators.append(f"Suspicious imports detected ({len(suspicious_imports)})")
            
            # Check for overlay (data after last section)
            has_overlay = False
            if len(pe.sections) > 0:
                last_section = pe.sections[-1]
                overlay_offset = last_section.PointerToRawData + last_section.SizeOfRawData
                
                if overlay_offset < len(file_data):
                    has_overlay = True
                    threat_score += 15
                    indicators.append("File has overlay data (common in packers)")
            
            # Check for missing imports (packed files often have few imports)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                import_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                if import_count < 5 and is_exe:
                    threat_score += 15
                    indicators.append(f"Very few imports ({import_count}) - possibly packed")
            
            # Suspicious strings detection (simplified)
            suspicious_strings = []
            string_data = file_data.decode('utf-8', errors='ignore')
            
            malware_keywords = ['keylog', 'backdoor', 'rootkit', 'botnet', 'ransomware']
            for keyword in malware_keywords:
                if keyword in string_data.lower():
                    suspicious_strings.append(keyword)
                    threat_score += 20
                    indicators.append(f"Suspicious string found: {keyword}")
            
            # Determine if threat
            if threat_score > 50:
                self.threats_detected += 1
            
            pe.close()
            
            return PEAnalysisResult(
                file_path=file_path,
                is_pe=True,
                is_dll=is_dll,
                is_driver=is_driver,
                is_packed=is_packed,
                entropy=file_entropy,
                suspicious_sections=suspicious_sections,
                suspicious_imports=suspicious_imports[:20],  # Limit to 20
                suspicious_strings=suspicious_strings,
                has_overlay=has_overlay,
                threat_score=min(threat_score, 100),
                indicators=indicators
            )
        
        except pefile.PEFormatError:
            logger.debug(f"{file_path} is not a valid PE file")
            return None
        except Exception as e:
            logger.error(f"Error analyzing PE file {file_path}: {e}")
            return None
    
    def get_statistics(self) -> Dict:
        """Get analyzer statistics"""
        return {
            "analyzed_files": self.analyzed_files,
            "threats_detected": self.threats_detected
        }


# Example usage
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python pe_analyzer.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    print(f"🔍 Analyzing PE file: {file_path}\n")
    
    analyzer = PEAnalyzer()
    result = analyzer.analyze_file(file_path)
    
    if result:
        print("=" * 60)
        print("PE ANALYSIS RESULT")
        print("=" * 60)
        print(f"File: {result.file_path}")
        print(f"Type: {'DLL' if result.is_dll else 'Driver' if result.is_driver else 'EXE'}")
        print(f"Entropy: {result.entropy:.2f}")
        print(f"Packed: {'⚠️ YES' if result.is_packed else '✅ NO'}")
        print(f"Overlay: {'⚠️ YES' if result.has_overlay else '✅ NO'}")
        print(f"\n🎯 Threat Score: {result.threat_score:.1f}/100")
        
        if result.indicators:
            print(f"\n⚠️ Indicators ({len(result.indicators)}):")
            for indicator in result.indicators:
                print(f"  - {indicator}")
        
        if result.suspicious_imports:
            print(f"\n🔍 Suspicious Imports ({len(result.suspicious_imports)}):")
            for imp in result.suspicious_imports[:10]:
                print(f"  - {imp}")
        
        if result.threat_score > 70:
            print("\n🚨 HIGH THREAT - Likely malware!")
        elif result.threat_score > 40:
            print("\n⚠️ SUSPICIOUS - Further investigation recommended")
        else:
            print("\n✅ LOW THREAT - File appears normal")
    else:
        print("❌ Not a valid PE file or analysis failed")