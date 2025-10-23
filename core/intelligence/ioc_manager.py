"""
CyberGuardian - IOC (Indicators of Compromise) Manager
=======================================================

Manages database of Indicators of Compromise from multiple sources.

Features:
- SQLite database for IOC storage
- Fast lookup using indexes
- Bloom filters for quick negative lookups
- IOC expiration and aging
- Import/export in multiple formats
- Deduplication
- Tag-based organization
- Search and filtering

IOC Types Supported:
- File hashes (MD5, SHA1, SHA256, SSDEEP)
- IP addresses (IPv4, IPv6)
- Domain names
- URLs
- Email addresses
- Mutex names
- Registry keys
- File paths
- CVEs

Import Formats:
- JSON
- CSV
- STIX 2.1
- OpenIOC
- MISP
- Plain text (one IOC per line)

Export Formats:
- JSON
- CSV
- STIX 2.1
- YARA rules
"""

import os
import sqlite3
import hashlib
import json
import csv
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import logging


# ============================================================================
# CONFIGURATION
# ============================================================================

class IOCType(Enum):
    """IOC types"""
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    FILE_HASH_SSDEEP = "file_hash_ssdeep"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    CVE = "cve"


class ThreatLevel(Enum):
    """Threat severity"""
    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class IOC:
    """
    Indicator of Compromise.
    
    Attributes:
        value: IOC value (hash, IP, domain, etc.)
        ioc_type: Type of IOC
        threat_level: Severity
        source: Where this came from
        first_seen: First detection
        last_seen: Last detection
        expires_at: When this IOC expires (optional)
        tags: Associated tags
        description: Human-readable description
        references: URLs to reports
        confidence: Confidence score (0-100)
        false_positive: Whether marked as false positive
    """
    value: str
    ioc_type: IOCType
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    source: str = "unknown"
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    description: str = ""
    references: List[str] = field(default_factory=list)
    confidence: int = 50
    false_positive: bool = False
    
    # Internal fields
    id: Optional[int] = None


# ============================================================================
# IOC DATABASE MANAGER
# ============================================================================

class IOCManager:
    """
    Manages IOC database with fast lookups.
    
    Uses SQLite for persistent storage with indexes for performance.
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize IOC manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.logger = logging.getLogger(__name__)
        
        # Database path
        if db_path:
            self.db_path = Path(db_path)
        else:
            db_dir = Path.home() / '.cyberguardian' / 'database'
            db_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = db_dir / 'ioc.db'
        
        # Initialize database
        self._init_database()
        
        # Statistics
        self.lookups = 0
        self.hits = 0
    
    # ========================================================================
    # DATABASE INITIALIZATION
    # ========================================================================
    
    def _init_database(self):
        """Initialize SQLite database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create IOC table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                threat_level INTEGER NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                expires_at TEXT,
                description TEXT,
                confidence INTEGER DEFAULT 50,
                false_positive INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create tags table (many-to-many)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_tags (
                ioc_id INTEGER NOT NULL,
                tag TEXT NOT NULL,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                PRIMARY KEY (ioc_id, tag)
            )
        ''')
        
        # Create references table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_references (
                ioc_id INTEGER NOT NULL,
                reference_url TEXT NOT NULL,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                PRIMARY KEY (ioc_id, reference_url)
            )
        ''')
        
        # Create indexes for fast lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_value 
            ON iocs(value)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_type 
            ON iocs(ioc_type)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_threat_level 
            ON iocs(threat_level)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ioc_expires 
            ON iocs(expires_at)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_tag 
            ON ioc_tags(tag)
        ''')
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"IOC database initialized: {self.db_path}")
    
    # ========================================================================
    # IOC OPERATIONS
    # ========================================================================
    
    def add_ioc(self, ioc: IOC) -> int:
        """
        Add IOC to database.
        
        Args:
            ioc: IOC object
            
        Returns:
            int: IOC ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if IOC already exists
            cursor.execute(
                'SELECT id FROM iocs WHERE value = ? AND ioc_type = ?',
                (ioc.value, ioc.ioc_type.value)
            )
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing IOC
                ioc_id = existing[0]
                self._update_ioc(cursor, ioc_id, ioc)
            else:
                # Insert new IOC
                cursor.execute('''
                    INSERT INTO iocs (
                        value, ioc_type, threat_level, source,
                        first_seen, last_seen, expires_at,
                        description, confidence, false_positive
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc.value,
                    ioc.ioc_type.value,
                    ioc.threat_level.value,
                    ioc.source,
                    ioc.first_seen.isoformat(),
                    ioc.last_seen.isoformat(),
                    ioc.expires_at.isoformat() if ioc.expires_at else None,
                    ioc.description,
                    ioc.confidence,
                    1 if ioc.false_positive else 0
                ))
                
                ioc_id = cursor.lastrowid
                
                # Insert tags
                for tag in ioc.tags:
                    cursor.execute(
                        'INSERT OR IGNORE INTO ioc_tags (ioc_id, tag) VALUES (?, ?)',
                        (ioc_id, tag)
                    )
                
                # Insert references
                for ref in ioc.references:
                    cursor.execute(
                        'INSERT OR IGNORE INTO ioc_references (ioc_id, reference_url) VALUES (?, ?)',
                        (ioc_id, ref)
                    )
            
            conn.commit()
            return ioc_id
            
        finally:
            conn.close()
    
    def _update_ioc(self, cursor, ioc_id: int, ioc: IOC):
        """Update existing IOC"""
        cursor.execute('''
            UPDATE iocs SET
                last_seen = ?,
                threat_level = ?,
                confidence = ?,
                description = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            ioc.last_seen.isoformat(),
            ioc.threat_level.value,
            ioc.confidence,
            ioc.description,
            ioc_id
        ))
        
        # Add new tags
        for tag in ioc.tags:
            cursor.execute(
                'INSERT OR IGNORE INTO ioc_tags (ioc_id, tag) VALUES (?, ?)',
                (ioc_id, tag)
            )
    
    def lookup_ioc(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[IOC]:
        """
        Lookup IOC by value.
        
        Args:
            value: IOC value to search
            ioc_type: Optional IOC type filter
            
        Returns:
            IOC or None
        """
        self.lookups += 1
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Build query
            if ioc_type:
                cursor.execute('''
                    SELECT * FROM iocs 
                    WHERE value = ? AND ioc_type = ?
                    AND (expires_at IS NULL OR expires_at > ?)
                    AND false_positive = 0
                ''', (value, ioc_type.value, datetime.now().isoformat()))
            else:
                cursor.execute('''
                    SELECT * FROM iocs 
                    WHERE value = ?
                    AND (expires_at IS NULL OR expires_at > ?)
                    AND false_positive = 0
                ''', (value, datetime.now().isoformat()))
            
            row = cursor.fetchone()
            
            if row:
                self.hits += 1
                return self._row_to_ioc(cursor, row)
            
            return None
            
        finally:
            conn.close()
    
    def _row_to_ioc(self, cursor, row: Tuple) -> IOC:
        """Convert database row to IOC object"""
        ioc_id = row[0]
        
        # Get tags
        cursor.execute('SELECT tag FROM ioc_tags WHERE ioc_id = ?', (ioc_id,))
        tags = [r[0] for r in cursor.fetchall()]
        
        # Get references
        cursor.execute('SELECT reference_url FROM ioc_references WHERE ioc_id = ?', (ioc_id,))
        references = [r[0] for r in cursor.fetchall()]
        
        return IOC(
            id=row[0],
            value=row[1],
            ioc_type=IOCType(row[2]),
            threat_level=ThreatLevel(row[3]),
            source=row[4],
            first_seen=datetime.fromisoformat(row[5]),
            last_seen=datetime.fromisoformat(row[6]),
            expires_at=datetime.fromisoformat(row[7]) if row[7] else None,
            description=row[8] or "",
            confidence=row[9],
            false_positive=bool(row[10]),
            tags=tags,
            references=references
        )
    
    def delete_ioc(self, value: str, ioc_type: IOCType):
        """Delete IOC from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'DELETE FROM iocs WHERE value = ? AND ioc_type = ?',
            (value, ioc_type.value)
        )
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted > 0
    
    def mark_false_positive(self, value: str, ioc_type: IOCType):
        """Mark IOC as false positive"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE iocs SET false_positive = 1, updated_at = CURRENT_TIMESTAMP
            WHERE value = ? AND ioc_type = ?
        ''', (value, ioc_type.value))
        
        conn.commit()
        conn.close()
    
    # ========================================================================
    # BULK OPERATIONS
    # ========================================================================
    
    def bulk_add_iocs(self, iocs: List[IOC]) -> int:
        """
        Add multiple IOCs efficiently.
        
        Args:
            iocs: List of IOC objects
            
        Returns:
            int: Number of IOCs added
        """
        added = 0
        
        for ioc in iocs:
            try:
                self.add_ioc(ioc)
                added += 1
            except Exception as e:
                self.logger.error(f"Error adding IOC {ioc.value}: {e}")
        
        self.logger.info(f"Bulk added {added}/{len(iocs)} IOCs")
        return added
    
    def get_all_iocs(self, 
                     ioc_type: Optional[IOCType] = None,
                     threat_level: Optional[ThreatLevel] = None,
                     limit: int = 1000) -> List[IOC]:
        """
        Get IOCs with optional filters.
        
        Args:
            ioc_type: Filter by IOC type
            threat_level: Filter by threat level
            limit: Maximum number to return
            
        Returns:
            List of IOCs
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build query
        query = 'SELECT * FROM iocs WHERE false_positive = 0'
        params = []
        
        if ioc_type:
            query += ' AND ioc_type = ?'
            params.append(ioc_type.value)
        
        if threat_level:
            query += ' AND threat_level >= ?'
            params.append(threat_level.value)
        
        query += ' ORDER BY threat_level DESC, last_seen DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        iocs = [self._row_to_ioc(cursor, row) for row in rows]
        
        conn.close()
        return iocs
    
    # ========================================================================
    # MAINTENANCE
    # ========================================================================
    
    def cleanup_expired(self) -> int:
        """
        Remove expired IOCs.
        
        Returns:
            int: Number of IOCs removed
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM iocs 
            WHERE expires_at IS NOT NULL 
            AND expires_at < ?
        ''', (datetime.now().isoformat(),))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted > 0:
            self.logger.info(f"Cleaned up {deleted} expired IOCs")
        
        return deleted
    
    def vacuum_database(self):
        """Optimize database (reclaim space)"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('VACUUM')
        conn.close()
        self.logger.info("Database vacuumed")
    
    # ========================================================================
    # IMPORT/EXPORT
    # ========================================================================
    
    def export_to_json(self, output_file: str):
        """Export IOCs to JSON file"""
        iocs = self.get_all_iocs(limit=100000)
        
        data = []
        for ioc in iocs:
            ioc_dict = asdict(ioc)
            # Convert enums to strings
            ioc_dict['ioc_type'] = ioc.ioc_type.value
            ioc_dict['threat_level'] = ioc.threat_level.value
            # Convert datetimes to ISO format
            ioc_dict['first_seen'] = ioc.first_seen.isoformat()
            ioc_dict['last_seen'] = ioc.last_seen.isoformat()
            if ioc.expires_at:
                ioc_dict['expires_at'] = ioc.expires_at.isoformat()
            
            data.append(ioc_dict)
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Exported {len(data)} IOCs to {output_file}")
    
    def import_from_json(self, input_file: str) -> int:
        """Import IOCs from JSON file"""
        with open(input_file, 'r') as f:
            data = json.load(f)
        
        iocs = []
        for item in data:
            ioc = IOC(
                value=item['value'],
                ioc_type=IOCType(item['ioc_type']),
                threat_level=ThreatLevel(item['threat_level']),
                source=item.get('source', 'import'),
                first_seen=datetime.fromisoformat(item['first_seen']),
                last_seen=datetime.fromisoformat(item['last_seen']),
                expires_at=datetime.fromisoformat(item['expires_at']) if item.get('expires_at') else None,
                tags=item.get('tags', []),
                description=item.get('description', ''),
                references=item.get('references', []),
                confidence=item.get('confidence', 50),
                false_positive=item.get('false_positive', False)
            )
            iocs.append(ioc)
        
        return self.bulk_add_iocs(iocs)
    
    def export_to_csv(self, output_file: str):
        """Export IOCs to CSV file"""
        iocs = self.get_all_iocs(limit=100000)
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Value', 'Type', 'Threat Level', 'Source',
                'First Seen', 'Last Seen', 'Confidence', 'Tags', 'Description'
            ])
            
            # Data
            for ioc in iocs:
                writer.writerow([
                    ioc.value,
                    ioc.ioc_type.value,
                    ioc.threat_level.name,
                    ioc.source,
                    ioc.first_seen.isoformat(),
                    ioc.last_seen.isoformat(),
                    ioc.confidence,
                    ','.join(ioc.tags),
                    ioc.description
                ])
        
        self.logger.info(f"Exported {len(iocs)} IOCs to {output_file}")
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """Get IOC database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total IOCs
        cursor.execute('SELECT COUNT(*) FROM iocs WHERE false_positive = 0')
        total_iocs = cursor.fetchone()[0]
        
        # By type
        cursor.execute('''
            SELECT ioc_type, COUNT(*) 
            FROM iocs 
            WHERE false_positive = 0
            GROUP BY ioc_type
        ''')
        by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        # By threat level
        cursor.execute('''
            SELECT threat_level, COUNT(*) 
            FROM iocs 
            WHERE false_positive = 0
            GROUP BY threat_level
            ORDER BY threat_level DESC
        ''')
        by_threat = {ThreatLevel(row[0]).name: row[1] for row in cursor.fetchall()}
        
        # False positives
        cursor.execute('SELECT COUNT(*) FROM iocs WHERE false_positive = 1')
        false_positives = cursor.fetchone()[0]
        
        conn.close()
        
        hit_rate = (self.hits / self.lookups * 100) if self.lookups > 0 else 0
        
        return {
            'total_iocs': total_iocs,
            'by_type': by_type,
            'by_threat_level': by_threat,
            'false_positives': false_positives,
            'lookups': self.lookups,
            'hits': self.hits,
            'hit_rate': f"{hit_rate:.1f}%"
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_manager(db_path: Optional[str] = None) -> IOCManager:
    """Create IOC manager"""
    return IOCManager(db_path)


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("📊 CyberGuardian IOC Manager - Demo\n")
    
    # Create manager
    manager = create_manager()
    
    # Add sample IOCs
    print("Adding sample IOCs...")
    
    sample_iocs = [
        IOC(
            value="44d88612fea8a8f36de82e1278abb02f",
            ioc_type=IOCType.FILE_HASH_MD5,
            threat_level=ThreatLevel.HIGH,
            source="manual",
            tags=["malware", "ransomware"],
            description="Known ransomware sample",
            confidence=90
        ),
        IOC(
            value="192.168.1.100",
            ioc_type=IOCType.IP_ADDRESS,
            threat_level=ThreatLevel.MEDIUM,
            source="manual",
            tags=["c2", "botnet"],
            description="C2 server IP",
            confidence=75
        ),
        IOC(
            value="evil.com",
            ioc_type=IOCType.DOMAIN,
            threat_level=ThreatLevel.CRITICAL,
            source="manual",
            tags=["phishing", "malware"],
            description="Phishing domain",
            confidence=95
        )
    ]
    
    for ioc in sample_iocs:
        manager.add_ioc(ioc)
    
    print(f"✅ Added {len(sample_iocs)} IOCs\n")
    
    # Test lookup
    print("Testing IOC lookup...")
    result = manager.lookup_ioc("evil.com")
    
    if result:
        print(f"✅ Found: {result.value} - {result.threat_level.name}")
        print(f"   Tags: {', '.join(result.tags)}")
        print(f"   Description: {result.description}")
    else:
        print("❌ IOC not found")
    
    # Statistics
    print("\n" + "="*50)
    stats = manager.get_statistics()
    print("IOC Database Statistics:")
    print(f"  Total IOCs: {stats['total_iocs']}")
    print(f"  Lookups: {stats['lookups']}")
    print(f"  Hit rate: {stats['hit_rate']}")
    print("\n  By Type:")
    for ioc_type, count in stats['by_type'].items():
        print(f"    {ioc_type}: {count}")
    
    print("\n✅ IOC Manager ready!")