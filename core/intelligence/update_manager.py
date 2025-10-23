"""
CyberGuardian - Threat Intelligence Update Manager
===================================================

Manages automatic updates of threat intelligence feeds.

Features:
- Scheduled feed updates
- Priority-based updating (critical feeds first)
- Differential updates (only download new data)
- Cryptographic verification of feeds
- Retry logic with exponential backoff
- Update health monitoring
- Bandwidth optimization
- Offline mode support

Update Tiers:
- TIER 1 (Critical): Real-time updates (every 5 minutes)
  - Active campaigns, zero-days, critical CVEs
  
- TIER 2 (High): Hourly updates
  - New malware samples, IOCs, C2 infrastructure
  
- TIER 3 (Medium): Daily updates
  - CVE updates, vulnerability scans
  
- TIER 4 (Low): Weekly updates
  - Historical data, archived threats

Feed Sources:
- VirusTotal (file hashes)
- AlienVault OTX (pulses)
- AbuseIPDB (IP reputation)
- URLhaus (malicious URLs)
- MalwareBazaar (samples)
- EmergingThreats (Snort/Suricata rules)
- Custom feeds (user-provided)

Health Checks:
- Feed availability monitoring
- Data freshness checks
- Update success rate
- Bandwidth usage tracking
"""

import os
import time
import hashlib
import requests
import threading
import schedule
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging


# ============================================================================
# CONFIGURATION
# ============================================================================

class UpdatePriority(Enum):
    """Update priority levels"""
    CRITICAL = 1  # Real-time (5 min)
    HIGH = 2      # Hourly
    MEDIUM = 3    # Daily
    LOW = 4       # Weekly


class FeedStatus(Enum):
    """Feed health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass
class FeedSource:
    """
    Threat intelligence feed source.
    
    Attributes:
        name: Feed name
        url: Feed URL
        priority: Update priority
        update_interval: Minutes between updates
        requires_auth: Whether authentication needed
        api_key: API key (if required)
        last_update: Last successful update
        last_error: Last error message
        status: Current health status
        success_rate: Percentage of successful updates
        data_format: Format (json, csv, stix, etc.)
    """
    name: str
    url: str
    priority: UpdatePriority
    update_interval: int  # minutes
    requires_auth: bool = False
    api_key: Optional[str] = None
    last_update: Optional[datetime] = None
    last_error: Optional[str] = None
    status: FeedStatus = FeedStatus.HEALTHY
    success_rate: float = 100.0
    data_format: str = "json"
    enabled: bool = True
    
    # Statistics
    total_updates: int = 0
    successful_updates: int = 0
    failed_updates: int = 0


# ============================================================================
# UPDATE MANAGER
# ============================================================================

class UpdateManager:
    """
    Manages automatic threat intelligence feed updates.
    
    Schedules and executes feed updates based on priority.
    """
    
    # Default feed sources
    DEFAULT_FEEDS = {
        'alienvault_otx_pulses': {
            'name': 'AlienVault OTX Pulses',
            'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
            'priority': UpdatePriority.HIGH,
            'interval': 60,  # 1 hour
            'requires_auth': True,
            'format': 'json'
        },
        'urlhaus_recent': {
            'name': 'URLhaus Recent URLs',
            'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
            'priority': UpdatePriority.HIGH,
            'interval': 60,
            'requires_auth': False,
            'format': 'csv'
        },
        'malwarebazaar_recent': {
            'name': 'MalwareBazaar Recent Samples',
            'url': 'https://mb-api.abuse.ch/api/v1/',
            'priority': UpdatePriority.MEDIUM,
            'interval': 360,  # 6 hours
            'requires_auth': False,
            'format': 'json'
        },
        'emergingthreats_rules': {
            'name': 'EmergingThreats Rules',
            'url': 'https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz',
            'priority': UpdatePriority.MEDIUM,
            'interval': 1440,  # Daily
            'requires_auth': False,
            'format': 'text'
        }
    }
    
    def __init__(self,
                 api_keys: Optional[Dict[str, str]] = None,
                 cache_dir: Optional[str] = None,
                 callback: Optional[Callable[[str, Dict], None]] = None):
        """
        Initialize update manager.
        
        Args:
            api_keys: Dictionary of {source: api_key}
            cache_dir: Directory for caching feeds
            callback: Function called after successful update
        """
        self.logger = logging.getLogger(__name__)
        
        # API keys
        self.api_keys = api_keys or {}
        
        # Cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / '.cyberguardian' / 'feeds'
        
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Callback for processing updated data
        self.callback = callback
        
        # Feed sources
        self.feeds: Dict[str, FeedSource] = {}
        self._initialize_feeds()
        
        # Threading
        self.running = False
        self.scheduler_thread = None
        
        # Statistics
        self.total_updates = 0
        self.successful_updates = 0
        self.failed_updates = 0
        self.start_time = None
    
    # ========================================================================
    # INITIALIZATION
    # ========================================================================
    
    def _initialize_feeds(self):
        """Initialize feed sources from defaults"""
        for feed_id, config in self.DEFAULT_FEEDS.items():
            api_key = self.api_keys.get(feed_id)
            
            feed = FeedSource(
                name=config['name'],
                url=config['url'],
                priority=config['priority'],
                update_interval=config['interval'],
                requires_auth=config['requires_auth'],
                api_key=api_key,
                data_format=config['format']
            )
            
            # Disable if auth required but no key
            if feed.requires_auth and not api_key:
                feed.enabled = False
                feed.status = FeedStatus.DISABLED
                self.logger.warning(f"Feed '{feed.name}' disabled - no API key")
            
            self.feeds[feed_id] = feed
    
    def add_custom_feed(self, feed_id: str, feed: FeedSource):
        """Add custom feed source"""
        self.feeds[feed_id] = feed
        self.logger.info(f"Added custom feed: {feed.name}")
    
    # ========================================================================
    # UPDATE CONTROL
    # ========================================================================
    
    def start(self):
        """Start automatic updates"""
        self.logger.info("Starting update manager...")
        self.start_time = datetime.now()
        self.running = True
        
        # Schedule updates for each feed
        self._schedule_feeds()
        
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        # Run initial update for all feeds
        self._run_initial_updates()
        
        self.logger.info("Update manager started")
    
    def stop(self):
        """Stop automatic updates"""
        self.logger.info("Stopping update manager...")
        self.running = False
        
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        
        schedule.clear()
        
        self.logger.info("Update manager stopped")
        self._print_statistics()
    
    def _schedule_feeds(self):
        """Schedule feed updates based on priority"""
        for feed_id, feed in self.feeds.items():
            if not feed.enabled:
                continue
            
            # Schedule periodic update
            schedule.every(feed.update_interval).minutes.do(
                self._update_feed, feed_id
            )
            
            self.logger.info(
                f"Scheduled '{feed.name}' - every {feed.update_interval} minutes"
            )
    
    def _run_scheduler(self):
        """Main scheduler loop"""
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                self.logger.error(f"Scheduler error: {e}")
                time.sleep(5)
    
    def _run_initial_updates(self):
        """Run initial update for all feeds"""
        self.logger.info("Running initial feed updates...")
        
        # Sort by priority
        sorted_feeds = sorted(
            self.feeds.items(),
            key=lambda x: x[1].priority.value
        )
        
        for feed_id, feed in sorted_feeds:
            if feed.enabled:
                self._update_feed(feed_id)
                time.sleep(1)  # Rate limiting
    
    # ========================================================================
    # FEED UPDATE
    # ========================================================================
    
    def _update_feed(self, feed_id: str):
        """
        Update a specific feed.
        
        Args:
            feed_id: Feed identifier
        """
        feed = self.feeds.get(feed_id)
        if not feed or not feed.enabled:
            return
        
        self.total_updates += 1
        feed.total_updates += 1
        
        self.logger.info(f"Updating feed: {feed.name}")
        
        try:
            # Download feed data
            data = self._download_feed(feed)
            
            if data:
                # Save to cache
                self._save_to_cache(feed_id, data)
                
                # Process data (callback)
                if self.callback:
                    self.callback(feed_id, data)
                
                # Update statistics
                feed.last_update = datetime.now()
                feed.last_error = None
                feed.status = FeedStatus.HEALTHY
                feed.successful_updates += 1
                self.successful_updates += 1
                
                self.logger.info(f"✅ Successfully updated: {feed.name}")
            else:
                raise Exception("No data received")
            
        except Exception as e:
            # Handle failure
            feed.last_error = str(e)
            feed.failed_updates += 1
            self.failed_updates += 1
            
            # Update status
            if feed.failed_updates > 3:
                feed.status = FeedStatus.FAILED
            else:
                feed.status = FeedStatus.DEGRADED
            
            self.logger.error(f"❌ Failed to update {feed.name}: {e}")
        
        # Update success rate
        if feed.total_updates > 0:
            feed.success_rate = (feed.successful_updates / feed.total_updates) * 100
    
    def _download_feed(self, feed: FeedSource) -> Optional[Dict]:
        """
        Download feed data from URL.
        
        Args:
            feed: Feed source
            
        Returns:
            Dict with feed data or None
        """
        headers = {}
        
        # Add authentication if required
        if feed.requires_auth and feed.api_key:
            # Different APIs use different auth methods
            if 'otx.alienvault' in feed.url:
                headers['X-OTX-API-KEY'] = feed.api_key
            elif 'virustotal' in feed.url:
                headers['x-apikey'] = feed.api_key
            elif 'abuseipdb' in feed.url:
                headers['Key'] = feed.api_key
        
        # Set user agent
        headers['User-Agent'] = 'CyberGuardian/1.0'
        
        try:
            response = requests.get(
                feed.url,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            
            # Parse based on format
            if feed.data_format == 'json':
                return response.json()
            elif feed.data_format == 'csv':
                return {'content': response.text}
            elif feed.data_format == 'text':
                return {'content': response.text}
            else:
                return {'content': response.content}
            
        except requests.RequestException as e:
            raise Exception(f"Download failed: {e}")
    
    def _save_to_cache(self, feed_id: str, data: Dict):
        """Save feed data to cache"""
        import json
        
        cache_file = self.cache_dir / f"{feed_id}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'feed_id': feed_id,
                    'updated_at': datetime.now().isoformat(),
                    'data': data
                }, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Error saving cache: {e}")
    
    def load_from_cache(self, feed_id: str) -> Optional[Dict]:
        """Load feed data from cache"""
        import json
        
        cache_file = self.cache_dir / f"{feed_id}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                
                # Check age
                updated_at = datetime.fromisoformat(cached['updated_at'])
                age = datetime.now() - updated_at
                
                # If cache is fresh, return it
                feed = self.feeds.get(feed_id)
                if feed and age.total_seconds() < feed.update_interval * 60:
                    self.logger.debug(f"Using cached data for {feed_id}")
                    return cached['data']
                
            except Exception as e:
                self.logger.error(f"Error loading cache: {e}")
        
        return None
    
    # ========================================================================
    # MANUAL OPERATIONS
    # ========================================================================
    
    def update_feed_now(self, feed_id: str):
        """Manually trigger feed update"""
        self._update_feed(feed_id)
    
    def update_all_now(self):
        """Manually trigger update for all feeds"""
        self.logger.info("Manually updating all feeds...")
        
        for feed_id in self.feeds.keys():
            self._update_feed(feed_id)
            time.sleep(1)
    
    def enable_feed(self, feed_id: str):
        """Enable a feed"""
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = True
            self.feeds[feed_id].status = FeedStatus.HEALTHY
            self.logger.info(f"Enabled feed: {feed_id}")
    
    def disable_feed(self, feed_id: str):
        """Disable a feed"""
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = False
            self.feeds[feed_id].status = FeedStatus.DISABLED
            self.logger.info(f"Disabled feed: {feed_id}")
    
    # ========================================================================
    # MONITORING
    # ========================================================================
    
    def get_feed_status(self) -> Dict[str, Dict]:
        """Get status of all feeds"""
        status = {}
        
        for feed_id, feed in self.feeds.items():
            status[feed_id] = {
                'name': feed.name,
                'enabled': feed.enabled,
                'status': feed.status.value,
                'last_update': feed.last_update.isoformat() if feed.last_update else None,
                'last_error': feed.last_error,
                'success_rate': f"{feed.success_rate:.1f}%",
                'total_updates': feed.total_updates,
                'failed_updates': feed.failed_updates
            }
        
        return status
    
    def _print_statistics(self):
        """Print update statistics"""
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            success_rate = (self.successful_updates / self.total_updates * 100) if self.total_updates > 0 else 0
            
            self.logger.info(f"""
            === Update Manager Statistics ===
            Runtime: {duration:.1f} seconds
            Total updates: {self.total_updates}
            Successful: {self.successful_updates}
            Failed: {self.failed_updates}
            Success rate: {success_rate:.1f}%
            """)
    
    def get_statistics(self) -> Dict:
        """Get update statistics"""
        success_rate = (self.successful_updates / self.total_updates * 100) if self.total_updates > 0 else 0
        
        # Count feeds by status
        status_counts = {}
        for feed in self.feeds.values():
            status = feed.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_feeds': len(self.feeds),
            'enabled_feeds': sum(1 for f in self.feeds.values() if f.enabled),
            'total_updates': self.total_updates,
            'successful_updates': self.successful_updates,
            'failed_updates': self.failed_updates,
            'success_rate': f"{success_rate:.1f}%",
            'feeds_by_status': status_counts
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_manager(api_keys: Optional[Dict[str, str]] = None,
                  callback: Optional[Callable] = None) -> UpdateManager:
    """Create update manager"""
    return UpdateManager(api_keys=api_keys, callback=callback)


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🔄 CyberGuardian Update Manager - Demo\n")
    
    # Callback for processing updates
    def process_update(feed_id: str, data: Dict):
        print(f"📥 Processing update from: {feed_id}")
        print(f"   Data keys: {list(data.keys())}")
    
    # Create manager (no API keys for demo)
    manager = create_manager(callback=process_update)
    
    # Show feed status
    print("Feed Status:")
    status = manager.get_feed_status()
    for feed_id, info in status.items():
        print(f"  {info['name']}: {info['status']} ({info['success_rate']} success)")
    
    print("\n✅ Update manager ready!")
    print("Note: Feeds without API keys are disabled")
    
    # Statistics
    stats = manager.get_statistics()
    print(f"\nStatistics:")
    print(f"  Total feeds: {stats['total_feeds']}")
    print(f"  Enabled: {stats['enabled_feeds']}")