"""
CyberGuardian AI - YARA Signature Engine
Real-time malware detection using YARA rules
"""

import yara
import os
import logging
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class YaraMatch:
    """YARA rule match result"""
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, str]
    strings: List[tuple]
    file_path: str
    timestamp: str

class YaraEngine:
    """
    YARA Signature Engine
    
    Features:
    - Load YARA rules from multiple sources
    - Scan files with compiled rules
    - Match detection and reporting
    - Rule compilation and caching
    """
    
    def __init__(self, rules_dir: str = "signatures"):
        """
        Initialize YARA engine
        
        Args:
            rules_dir: Directory containing YARA rule files
        """
        self.rules_dir = Path(rules_dir)
        self.compiled_rules = None
        self.rules_loaded = False
        
        # Statistics
        self.total_rules = 0
        self.scans_performed = 0
        self.matches_found = 0
        
        logger.info(f"YARA Engine initialized with rules directory: {self.rules_dir}")
    
    def load_rules(self) -> bool:
        """
        Load and compile all YARA rules from rules directory
        
        Returns:
            True if rules loaded successfully, False otherwise
        """
        try:
            if not self.rules_dir.exists():
                logger.error(f"Rules directory not found: {self.rules_dir}")
                return False
            
            # Collect all .yar and .yara files
            rule_files = {}
            for root, dirs, files in os.walk(self.rules_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        file_path = os.path.join(root, file)
                        namespace = os.path.relpath(root, self.rules_dir).replace(os.sep, '_')
                        rule_name = f"{namespace}_{file}"
                        rule_files[rule_name] = file_path
            
            if not rule_files:
                logger.warning("No YARA rules found in directory")
                return False
            
            # Compile rules
            self.compiled_rules = yara.compile(filepaths=rule_files)
            self.total_rules = len(rule_files)
            self.rules_loaded = True
            
            logger.info(f"✅ Loaded {self.total_rules} YARA rules successfully")
            return True
            
        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return False
    
    def scan_file(self, file_path: str) -> List[YaraMatch]:
        """
        Scan a file with loaded YARA rules
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of YARA matches
        """
        if not self.rules_loaded:
            logger.warning("YARA rules not loaded, attempting to load...")
            if not self.load_rules():
                return []
        
        try:
            matches = []
            self.scans_performed += 1
            
            # Scan file
            yara_matches = self.compiled_rules.match(file_path)
            
            if yara_matches:
                self.matches_found += len(yara_matches)
                
                for match in yara_matches:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        namespace=match.namespace,
                        tags=list(match.tags),
                        meta=dict(match.meta),
                        strings=[(s.identifier, s.instances) for s in match.strings],
                        file_path=file_path,
                        timestamp=datetime.now().isoformat()
                    )
                    matches.append(yara_match)
                    
                logger.info(f"🚨 YARA match: {match.rule} in {file_path}")
            
            return matches
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
            return []
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[YaraMatch]:
        """
        Scan all files in a directory
        
        Args:
            directory: Directory to scan
            recursive: Scan subdirectories
            
        Returns:
            List of all YARA matches
        """
        all_matches = []
        dir_path = Path(directory)
        
        if not dir_path.exists():
            logger.error(f"Directory not found: {directory}")
            return []
        
        # Get all files
        if recursive:
            files = [f for f in dir_path.rglob('*') if f.is_file()]
        else:
            files = [f for f in dir_path.iterdir() if f.is_file()]
        
        logger.info(f"Scanning {len(files)} files in {directory}")
        
        for file_path in files:
            try:
                matches = self.scan_file(str(file_path))
                all_matches.extend(matches)
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")
        
        logger.info(f"Scan complete: {len(all_matches)} matches found")
        return all_matches
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get engine statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            "rules_loaded": self.total_rules,
            "scans_performed": self.scans_performed,
            "matches_found": self.matches_found,
            "rules_directory": str(self.rules_dir),
            "engine_ready": self.rules_loaded
        }
    
    def reload_rules(self) -> bool:
        """
        Reload YARA rules from disk
        
        Returns:
            True if successful
        """
        logger.info("Reloading YARA rules...")
        self.compiled_rules = None
        self.rules_loaded = False
        return self.load_rules()


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("🔍 Testing YARA Engine...")
    
    # Initialize engine
    engine = YaraEngine()
    
    # Load rules
    if engine.load_rules():
        print(f"✅ Loaded {engine.total_rules} YARA rules")
        
        # Test scan if file path provided
        if len(sys.argv) > 1:
            test_file = sys.argv[1]
            print(f"\n📁 Scanning: {test_file}")
            
            matches = engine.scan_file(test_file)
            
            if matches:
                print(f"\n🚨 Found {len(matches)} matches:")
                for match in matches:
                    print(f"\n  Rule: {match.rule_name}")
                    print(f"  Tags: {', '.join(match.tags)}")
                    print(f"  Meta: {match.meta}")
            else:
                print("\n✅ No threats detected")
        
        # Show statistics
        stats = engine.get_statistics()
        print(f"\n📊 Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    else:
        print("❌ Failed to load YARA rules")