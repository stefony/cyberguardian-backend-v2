"""
CyberGuardian AI - Heuristic Analysis Engine
Unified heuristic analysis for PE and ELF files
"""

import os
import logging
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from datetime import datetime

from core.pe_analyzer import PEAnalyzer, PEAnalysisResult
from core.elf_analyzer import ELFAnalyzer, ELFAnalysisResult

logger = logging.getLogger(__name__)

@dataclass
class HeuristicResult:
    """Unified heuristic analysis result"""
    file_path: str
    file_type: str  # 'PE', 'ELF', 'Unknown'
    file_size: int
    threat_score: float
    threat_level: str  # 'safe', 'suspicious', 'dangerous'
    is_packed: bool
    entropy: float
    indicators: List[str]
    analysis_details: Union[PEAnalysisResult, ELFAnalysisResult, None]
    timestamp: str

class HeuristicEngine:
    """
    Unified Heuristic Analysis Engine
    
    Provides heuristic-based threat detection for:
    - Windows PE files (EXE, DLL, SYS)
    - Linux ELF files
    - Generic file analysis
    
    Features:
    - Automatic file type detection
    - PE/ELF specific analysis
    - Entropy-based packing detection
    - Suspicious behavior detection
    - Threat scoring and classification
    """
    
    def __init__(self):
        """Initialize heuristic engine"""
        self.pe_analyzer = PEAnalyzer()
        self.elf_analyzer = ELFAnalyzer()
        
        self.total_scans = 0
        self.threats_detected = 0
        
        logger.info("Heuristic Engine initialized")
    
    def detect_file_type(self, file_path: str) -> str:
        """
        Detect file type by magic bytes
        
        Args:
            file_path: Path to file
            
        Returns:
            File type: 'PE', 'ELF', or 'Unknown'
        """
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                
                # PE format: MZ header
                if magic[:2] == b'MZ':
                    return 'PE'
                
                # ELF format: \x7fELF
                if magic[:4] == b'\x7fELF':
                    return 'ELF'
                
                return 'Unknown'
        except Exception as e:
            logger.error(f"Error detecting file type for {file_path}: {e}")
            return 'Unknown'
    
    def analyze_file(self, file_path: str) -> HeuristicResult:
        """
        Perform heuristic analysis on file
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            HeuristicResult with analysis details
        """
        self.total_scans += 1
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return self._create_error_result(file_path, "File not found")
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Detect file type
        file_type = self.detect_file_type(file_path)
        
        # Perform type-specific analysis
        analysis_details = None
        
        if file_type == 'PE':
            analysis_details = self.pe_analyzer.analyze_file(file_path)
        elif file_type == 'ELF':
            analysis_details = self.elf_analyzer.analyze_file(file_path)
        
        # Build unified result
        if analysis_details:
            threat_score = analysis_details.threat_score
            indicators = analysis_details.indicators
            is_packed = analysis_details.is_packed
            entropy = analysis_details.entropy
        else:
            # Unknown file type - basic analysis
            threat_score = 0.0
            indicators = ["Unknown file type - limited analysis"]
            is_packed = False
            entropy = 0.0
        
        # Determine threat level
        if threat_score >= 70:
            threat_level = "dangerous"
            self.threats_detected += 1
        elif threat_score >= 40:
            threat_level = "suspicious"
        else:
            threat_level = "safe"
        
        return HeuristicResult(
            file_path=file_path,
            file_type=file_type,
            file_size=file_size,
            threat_score=threat_score,
            threat_level=threat_level,
            is_packed=is_packed,
            entropy=entropy,
            indicators=indicators,
            analysis_details=analysis_details,
            timestamp=datetime.now().isoformat()
        )
    
    def analyze_directory(self, directory: str, recursive: bool = False) -> List[HeuristicResult]:
        """
        Analyze all files in directory
        
        Args:
            directory: Directory path
            recursive: Scan subdirectories
            
        Returns:
            List of analysis results
        """
        results = []
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        result = self.analyze_file(file_path)
                        results.append(result)
            else:
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        result = self.analyze_file(file_path)
                        results.append(result)
        except Exception as e:
            logger.error(f"Error analyzing directory {directory}: {e}")
        
        return results
    
    def _create_error_result(self, file_path: str, error: str) -> HeuristicResult:
        """Create error result"""
        return HeuristicResult(
            file_path=file_path,
            file_type="Unknown",
            file_size=0,
            threat_score=0.0,
            threat_level="safe",
            is_packed=False,
            entropy=0.0,
            indicators=[f"Error: {error}"],
            analysis_details=None,
            timestamp=datetime.now().isoformat()
        )
    
    def get_statistics(self) -> Dict:
        """Get engine statistics"""
        pe_stats = self.pe_analyzer.get_statistics()
        elf_stats = self.elf_analyzer.get_statistics()
        
        return {
            "total_scans": self.total_scans,
            "threats_detected": self.threats_detected,
            "pe_files_analyzed": pe_stats["analyzed_files"],
            "pe_threats_detected": pe_stats["threats_detected"],
            "elf_files_analyzed": elf_stats["analyzed_files"],
            "elf_threats_detected": elf_stats["threats_detected"]
        }


# Example usage
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if len(sys.argv) < 2:
        print("Usage: python heuristics.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    print("🔍 CyberGuardian Heuristic Analysis")
    print("=" * 60)
    
    engine = HeuristicEngine()
    result = engine.analyze_file(file_path)
    
    print(f"\n📁 File: {result.file_path}")
    print(f"📊 Type: {result.file_type}")
    print(f"📏 Size: {result.file_size:,} bytes")
    print(f"📈 Entropy: {result.entropy:.2f}")
    print(f"📦 Packed: {'⚠️ YES' if result.is_packed else '✅ NO'}")
    print(f"\n🎯 Threat Score: {result.threat_score:.1f}/100")
    print(f"⚠️  Threat Level: {result.threat_level.upper()}")
    
    if result.indicators:
        print(f"\n🔍 Indicators ({len(result.indicators)}):")
        for indicator in result.indicators:
            print(f"  - {indicator}")
    
    if result.threat_level == "dangerous":
        print("\n🚨 HIGH THREAT - Quarantine recommended!")
    elif result.threat_level == "suspicious":
        print("\n⚠️ SUSPICIOUS - Further investigation recommended")
    else:
        print("\n✅ LOW THREAT - File appears safe")
    
    # Show statistics
    stats = engine.get_statistics()
    print(f"\n📊 Statistics:")
    print(f"  Total scans: {stats['total_scans']}")
    print(f"  Threats detected: {stats['threats_detected']}")