"""
CyberGuardian AI - ELF (Executable and Linkable Format) Analyzer
Linux executable heuristic analysis
"""

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import math
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ELFAnalysisResult:
    """ELF analysis result"""
    file_path: str
    is_elf: bool
    is_64bit: bool
    is_stripped: bool
    is_packed: bool
    entropy: float
    suspicious_sections: List[str]
    suspicious_symbols: List[str]
    has_unusual_entry: bool
    threat_score: float
    indicators: List[str]

class ELFAnalyzer:
    """
    ELF File Heuristic Analyzer
    
    Analyzes Linux executables for suspicious characteristics:
    - File entropy (packed/encrypted detection)
    - Suspicious symbols
    - Section analysis
    - Entry point validation
    - Stripped binaries
    """
    
    # Suspicious function names
    SUSPICIOUS_SYMBOLS = [
        # Network
        'socket', 'bind', 'listen', 'accept', 'connect',
        'sendto', 'recvfrom', 'setsockopt',
        
        # Process manipulation
        'fork', 'execve', 'system', 'popen', 'ptrace',
        
        # File operations
        'unlink', 'rmdir', 'chmod', 'chown',
        
        # Crypto
        'crypt', 'encrypt', 'decrypt',
        
        # Rootkit indicators
        'hide', 'hook', 'inject', 'rootkit'
    ]
    
    # Suspicious section names
    SUSPICIOUS_SECTIONS = [
        '.upx', '.packed', '.encrypted', '.obfuscated'
    ]
    
    def __init__(self):
        """Initialize ELF analyzer"""
        self.analyzed_files = 0
        self.threats_detected = 0
    
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to analyze
            
        Returns:
            Entropy value (0.0 - 8.0)
        """
        if not data:
            return 0.0
        
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for freq in frequencies:
            if freq > 0:
                probability = freq / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_file(self, file_path: str) -> Optional[ELFAnalysisResult]:
        """
        Analyze ELF file for suspicious characteristics
        
        Args:
            file_path: Path to ELF file
            
        Returns:
            ELFAnalysisResult or None if not an ELF file
        """
        try:
            with open(file_path, 'rb') as f:
                elffile = ELFFile(f)
                self.analyzed_files += 1
                
                indicators = []
                threat_score = 0.0
                
                # Basic file info
                is_64bit = elffile.elfclass == 64
                
                # Read entire file for entropy
                f.seek(0)
                file_data = f.read()
                file_entropy = self.calculate_entropy(file_data)
                
                # Check for packing
                is_packed = file_entropy > 7.0
                if is_packed:
                    threat_score += 20
                    indicators.append(f"High entropy ({file_entropy:.2f}) - likely packed")
                
                # Analyze sections
                suspicious_sections = []
                for section in elffile.iter_sections():
                    section_name = section.name
                    
                    # Check for suspicious section names
                    if any(susp in section_name.lower() for susp in self.SUSPICIOUS_SECTIONS):
                        suspicious_sections.append(section_name)
                        threat_score += 15
                        indicators.append(f"Suspicious section: {section_name}")
                    
                    # Check section entropy
                    section_data = section.data()
                    if len(section_data) > 0:
                        section_entropy = self.calculate_entropy(section_data)
                        
                        if section_entropy > 7.5:
                            threat_score += 10
                            indicators.append(f"High entropy in {section_name} ({section_entropy:.2f})")
                    
                    # Check for executable + writable sections
                    if section['sh_flags'] & 0x1 and section['sh_flags'] & 0x4:  # WRITE + EXEC
                        threat_score += 20
                        indicators.append(f"Writable + executable section: {section_name}")
                
                # Analyze symbols
                suspicious_symbols = []
                is_stripped = True
                
                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        is_stripped = False
                        
                        for symbol in section.iter_symbols():
                            sym_name = symbol.name
                            
                            if any(susp in sym_name.lower() for susp in self.SUSPICIOUS_SYMBOLS):
                                suspicious_symbols.append(sym_name)
                
                # Stripped binaries are more suspicious
                if is_stripped:
                    threat_score += 15
                    indicators.append("Binary is stripped (no symbol table)")
                
                # Score based on suspicious symbols
                if len(suspicious_symbols) > 10:
                    threat_score += 25
                    indicators.append(f"Many suspicious symbols ({len(suspicious_symbols)})")
                elif len(suspicious_symbols) > 5:
                    threat_score += 15
                    indicators.append(f"Multiple suspicious symbols ({len(suspicious_symbols)})")
                elif len(suspicious_symbols) > 0:
                    threat_score += 10
                    indicators.append(f"Suspicious symbols detected ({len(suspicious_symbols)})")
                
                # Check entry point
                entry_point = elffile.header['e_entry']
                has_unusual_entry = entry_point == 0 or entry_point > 0x10000000
                
                if has_unusual_entry:
                    threat_score += 15
                    indicators.append(f"Unusual entry point: 0x{entry_point:x}")
                
                # Check for suspicious strings
                string_data = file_data.decode('utf-8', errors='ignore')
                malware_keywords = ['backdoor', 'rootkit', 'payload', 'exploit']
                
                for keyword in malware_keywords:
                    if keyword in string_data.lower():
                        threat_score += 20
                        indicators.append(f"Suspicious string: {keyword}")
                
                # Determine if threat
                if threat_score > 50:
                    self.threats_detected += 1
                
                return ELFAnalysisResult(
                    file_path=file_path,
                    is_elf=True,
                    is_64bit=is_64bit,
                    is_stripped=is_stripped,
                    is_packed=is_packed,
                    entropy=file_entropy,
                    suspicious_sections=suspicious_sections,
                    suspicious_symbols=suspicious_symbols[:20],
                    has_unusual_entry=has_unusual_entry,
                    threat_score=min(threat_score, 100),
                    indicators=indicators
                )
        
        except Exception as e:
            logger.debug(f"{file_path} is not a valid ELF file: {e}")
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
        print("Usage: python elf_analyzer.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    print(f"🔍 Analyzing ELF file: {file_path}\n")
    
    analyzer = ELFAnalyzer()
    result = analyzer.analyze_file(file_path)
    
    if result:
        print("=" * 60)
        print("ELF ANALYSIS RESULT")
        print("=" * 60)
        print(f"File: {result.file_path}")
        print(f"Architecture: {'64-bit' if result.is_64bit else '32-bit'}")
        print(f"Entropy: {result.entropy:.2f}")
        print(f"Stripped: {'⚠️ YES' if result.is_stripped else '✅ NO'}")
        print(f"Packed: {'⚠️ YES' if result.is_packed else '✅ NO'}")
        print(f"\n🎯 Threat Score: {result.threat_score:.1f}/100")
        
        if result.indicators:
            print(f"\n⚠️ Indicators ({len(result.indicators)}):")
            for indicator in result.indicators:
                print(f"  - {indicator}")
        
        if result.suspicious_symbols:
            print(f"\n🔍 Suspicious Symbols ({len(result.suspicious_symbols)}):")
            for sym in result.suspicious_symbols[:10]:
                print(f"  - {sym}")
        
        if result.threat_score > 70:
            print("\n🚨 HIGH THREAT - Likely malware!")
        elif result.threat_score > 40:
            print("\n⚠️ SUSPICIOUS - Further investigation recommended")
        else:
            print("\n✅ LOW THREAT - File appears normal")
    else:
        print("❌ Not a valid ELF file or analysis failed")