"""
CyberGuardian - Alert System
=============================

Intelligent alert management and notification system.

Features:
- Multi-channel notifications (email, SMS, webhook, desktop)
- Alert prioritization
- Alert correlation (group related alerts)
- Alert suppression (reduce noise)
- Alert escalation
- Alert acknowledgment
- Alert history
- Customizable rules

Alert Severity:
- INFO: Informational events
- LOW: Minor issues
- MEDIUM: Suspicious activity
- HIGH: Confirmed threats
- CRITICAL: Active attacks

Alert Channels:
- Desktop notifications
- Email
- SMS (via Twilio)
- Webhook (Slack, Teams, etc.)
- Syslog
- SIEM integration

Noise Reduction:
- Alert deduplication
- Time-based throttling
- Correlation grouping
- False positive learning

Alert Workflow:
1. Detection event occurs
2. Alert created with context
3. Severity assessment
4. Correlation check
5. Suppression check
6. Notification dispatch
7. Alert logging
8. Escalation (if unacknowledged)
"""

import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import logging


# ============================================================================
# CONFIGURATION
# ============================================================================

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class AlertChannel(Enum):
    """Alert notification channels"""
    DESKTOP = "desktop"
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    SYSLOG = "syslog"
    LOG_FILE = "log_file"


class AlertStatus(Enum):
    """Alert status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Alert:
    """
    Security alert.
    
    Attributes:
        alert_id: Unique identifier
        title: Alert title
        description: Detailed description
        severity: Alert severity
        category: Alert category
        source: Detection source
        timestamp: When alert was created
        context: Additional context data
        mitre_techniques: MITRE ATT&CK techniques
        recommendations: Recommended actions
        status: Alert status
        acknowledged_by: Who acknowledged
        acknowledged_at: When acknowledged
    """
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    category: str
    source: str
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.name,
            'category': self.category,
            'source': self.source,
            'timestamp': self.timestamp.isoformat(),
            'context': self.context,
            'mitre_techniques': self.mitre_techniques,
            'recommendations': self.recommendations,
            'status': self.status.value
        }


# ============================================================================
# ALERT SYSTEM
# ============================================================================

class AlertSystem:
    """
    Intelligent alert management system.
    
    Handles alert creation, notification, and lifecycle.
    """
    
    def __init__(self):
        """Initialize alert system"""
        self.logger = logging.getLogger(__name__)
        
        # Alert storage
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=10000)
        
        # Alert counters
        self.alert_counter = 0
        
        # Notification callbacks
        self.notification_handlers: Dict[AlertChannel, Callable] = {}
        
        # Alert suppression (prevent alert flood)
        self.recent_alerts: Dict[str, datetime] = {}  # key -> last_seen
        self.suppression_window = timedelta(minutes=5)
        
        # Alert correlation (group similar alerts)
        self.correlation_groups: Dict[str, List[str]] = defaultdict(list)
        
        # Statistics
        self.alerts_created = 0
        self.alerts_acknowledged = 0
        self.alerts_resolved = 0
        self.notifications_sent = 0
        
        # Register default handlers
        self._register_default_handlers()
    
    # ========================================================================
    # ALERT CREATION
    # ========================================================================
    
    def create_alert(self,
                    title: str,
                    description: str,
                    severity: AlertSeverity,
                    category: str,
                    source: str,
                    context: Optional[Dict] = None,
                    mitre_techniques: Optional[List[str]] = None,
                    recommendations: Optional[List[str]] = None) -> Alert:
        """
        Create new alert.
        
        Args:
            title: Alert title
            description: Detailed description
            severity: Alert severity
            category: Alert category
            source: Detection source
            context: Additional context
            mitre_techniques: MITRE ATT&CK techniques
            recommendations: Recommended actions
            
        Returns:
            Alert object
        """
        self.alerts_created += 1
        self.alert_counter += 1
        
        # Generate alert ID
        alert_id = f"ALERT-{self.alert_counter:06d}"
        
        # Create alert
        alert = Alert(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            source=source,
            context=context or {},
            mitre_techniques=mitre_techniques or [],
            recommendations=recommendations or []
        )
        
        # Check suppression
        if self._should_suppress(alert):
            self.logger.debug(f"Alert suppressed: {title}")
            return alert
        
        # Store alert
        self.alerts[alert_id] = alert
        self.alert_history.append(alert)
        
        # Update suppression tracking
        suppression_key = self._get_suppression_key(alert)
        self.recent_alerts[suppression_key] = datetime.now()
        
        # Correlation
        self._correlate_alert(alert)
        
        # Log alert
        self.logger.warning(
            f"🚨 [{severity.name}] {title}\n"
            f"   Category: {category}\n"
            f"   Source: {source}\n"
            f"   Description: {description}"
        )
        
        # Send notifications
        self._send_notifications(alert)
        
        return alert
    
    def _should_suppress(self, alert: Alert) -> bool:
        """
        Check if alert should be suppressed.
        
        Suppresses duplicate alerts within time window.
        """
        suppression_key = self._get_suppression_key(alert)
        
        if suppression_key in self.recent_alerts:
            last_seen = self.recent_alerts[suppression_key]
            time_since = datetime.now() - last_seen
            
            if time_since < self.suppression_window:
                return True
        
        return False
    
    def _get_suppression_key(self, alert: Alert) -> str:
        """Generate suppression key for alert"""
        # Use title + category as key
        return f"{alert.title}:{alert.category}"
    
    # ========================================================================
    # ALERT CORRELATION
    # ========================================================================
    
    def _correlate_alert(self, alert: Alert):
        """
        Correlate alert with similar alerts.
        
        Groups related alerts together for easier analysis.
        """
        correlation_key = f"{alert.category}:{alert.severity.name}"
        
        self.correlation_groups[correlation_key].append(alert.alert_id)
        
        # Log if multiple correlated alerts
        group_size = len(self.correlation_groups[correlation_key])
        if group_size > 1:
            self.logger.info(
                f"Alert correlated: {alert.alert_id} "
                f"(group: {correlation_key}, size: {group_size})"
            )
    
    def get_correlated_alerts(self, alert_id: str) -> List[Alert]:
        """Get alerts correlated with given alert"""
        alert = self.alerts.get(alert_id)
        if not alert:
            return []
        
        correlation_key = f"{alert.category}:{alert.severity.name}"
        correlated_ids = self.correlation_groups.get(correlation_key, [])
        
        return [
            self.alerts[aid] for aid in correlated_ids
            if aid in self.alerts and aid != alert_id
        ]
    
    # ========================================================================
    # NOTIFICATIONS
    # ========================================================================
    
    def register_handler(self, channel: AlertChannel, handler: Callable):
        """
        Register notification handler.
        
        Args:
            channel: Notification channel
            handler: Handler function (takes Alert object)
        """
        self.notification_handlers[channel] = handler
        self.logger.info(f"Registered handler for {channel.value}")
    
    def _register_default_handlers(self):
        """Register default notification handlers"""
        
        # Desktop notification handler
        def desktop_handler(alert: Alert):
            self.logger.info(f"[DESKTOP] {alert.severity.name}: {alert.title}")
        
        # Log file handler
        def log_handler(alert: Alert):
            self.logger.info(f"[ALERT] {json.dumps(alert.to_dict())}")
        
        self.register_handler(AlertChannel.DESKTOP, desktop_handler)
        self.register_handler(AlertChannel.LOG_FILE, log_handler)
    
    def _send_notifications(self, alert: Alert):
        """Send notifications through all channels"""
        
        # Determine which channels to use based on severity
        channels = self._get_notification_channels(alert.severity)
        
        for channel in channels:
            if channel in self.notification_handlers:
                try:
                    self.notification_handlers[channel](alert)
                    self.notifications_sent += 1
                except Exception as e:
                    self.logger.error(f"Error sending to {channel.value}: {e}")
    
    def _get_notification_channels(self, severity: AlertSeverity) -> List[AlertChannel]:
        """Get notification channels based on severity"""
        if severity == AlertSeverity.CRITICAL:
            return [AlertChannel.DESKTOP, AlertChannel.EMAIL, AlertChannel.WEBHOOK, AlertChannel.LOG_FILE]
        elif severity == AlertSeverity.HIGH:
            return [AlertChannel.DESKTOP, AlertChannel.EMAIL, AlertChannel.LOG_FILE]
        elif severity == AlertSeverity.MEDIUM:
            return [AlertChannel.DESKTOP, AlertChannel.LOG_FILE]
        else:
            return [AlertChannel.LOG_FILE]
    
    # ========================================================================
    # ALERT MANAGEMENT
    # ========================================================================
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "user"):
        """Acknowledge alert"""
        alert = self.alerts.get(alert_id)
        if alert:
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_at = datetime.now()
            
            self.alerts_acknowledged += 1
            
            self.logger.info(f"Alert acknowledged: {alert_id} by {acknowledged_by}")
    
    def resolve_alert(self, alert_id: str):
        """Mark alert as resolved"""
        alert = self.alerts.get(alert_id)
        if alert:
            alert.status = AlertStatus.RESOLVED
            self.alerts_resolved += 1
            
            self.logger.info(f"Alert resolved: {alert_id}")
    
    def mark_false_positive(self, alert_id: str):
        """Mark alert as false positive"""
        alert = self.alerts.get(alert_id)
        if alert:
            alert.status = AlertStatus.FALSE_POSITIVE
            
            # Add to suppression (learn from false positives)
            suppression_key = self._get_suppression_key(alert)
            self.recent_alerts[suppression_key] = datetime.now() + timedelta(days=7)
            
            self.logger.info(f"Alert marked as false positive: {alert_id}")
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get alert by ID"""
        return self.alerts.get(alert_id)
    
    def get_alerts(self,
                   severity: Optional[AlertSeverity] = None,
                   status: Optional[AlertStatus] = None,
                   category: Optional[str] = None,
                   limit: int = 100) -> List[Alert]:
        """
        Get alerts with filters.
        
        Args:
            severity: Filter by severity
            status: Filter by status
            category: Filter by category
            limit: Maximum alerts to return
            
        Returns:
            List of Alert objects
        """
        results = list(self.alerts.values())
        
        # Apply filters
        if severity:
            results = [a for a in results if a.severity == severity]
        
        if status:
            results = [a for a in results if a.status == status]
        
        if category:
            results = [a for a in results if a.category == category]
        
        # Sort by timestamp (newest first)
        results.sort(key=lambda a: a.timestamp, reverse=True)
        
        return results[:limit]
    
    def get_unacknowledged_alerts(self) -> List[Alert]:
        """Get all unacknowledged alerts"""
        return [
            alert for alert in self.alerts.values()
            if alert.status == AlertStatus.NEW
        ]
    
    # ========================================================================
    # STATISTICS & REPORTING
    # ========================================================================
    
    def get_statistics(self) -> Dict:
        """Get alert system statistics"""
        # Count by severity
        by_severity = {}
        for severity in AlertSeverity:
            by_severity[severity.name] = sum(
                1 for a in self.alerts.values()
                if a.severity == severity
            )
        
        # Count by status
        by_status = {}
        for status in AlertStatus:
            by_status[status.value] = sum(
                1 for a in self.alerts.values()
                if a.status == status
            )
        
        return {
            'total_alerts': self.alerts_created,
            'active_alerts': len(self.alerts),
            'acknowledged': self.alerts_acknowledged,
            'resolved': self.alerts_resolved,
            'notifications_sent': self.notifications_sent,
            'by_severity': by_severity,
            'by_status': by_status,
            'correlation_groups': len(self.correlation_groups)
        }
    
    def generate_report(self, hours: int = 24) -> str:
        """
        Generate alert report for time period.
        
        Args:
            hours: Hours to include in report
            
        Returns:
            Formatted report string
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        
        recent_alerts = [
            a for a in self.alerts.values()
            if a.timestamp > cutoff
        ]
        
        report = []
        report.append("="*60)
        report.append(f"Alert Report - Last {hours} Hours")
        report.append("="*60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        report.append(f"Total Alerts: {len(recent_alerts)}")
        report.append("")
        
        # By severity
        report.append("By Severity:")
        for severity in AlertSeverity:
            count = sum(1 for a in recent_alerts if a.severity == severity)
            if count > 0:
                report.append(f"  {severity.name}: {count}")
        
        report.append("")
        
        # Critical alerts
        critical = [a for a in recent_alerts if a.severity == AlertSeverity.CRITICAL]
        if critical:
            report.append("Critical Alerts:")
            for alert in critical[:10]:
                report.append(f"  [{alert.alert_id}] {alert.title}")
                report.append(f"    Time: {alert.timestamp.strftime('%H:%M:%S')}")
                report.append(f"    Status: {alert.status.value}")
        
        return "\n".join(report)


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_alert_system() -> AlertSystem:
    """Create alert system"""
    return AlertSystem()


# ============================================================================
# TESTING & DEMO
# ============================================================================

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("🔔 CyberGuardian Alert System - Demo\n")
    
    # Create alert system
    alert_system = create_alert_system()
    
    # Create sample alerts
    print("Creating sample alerts...\n")
    
    alert1 = alert_system.create_alert(
        title="Ransomware Activity Detected",
        description="Mass file encryption detected in Documents folder",
        severity=AlertSeverity.CRITICAL,
        category="malware",
        source="behavioral_engine",
        context={'files_encrypted': 150, 'location': 'C:\\Users\\Test\\Documents'},
        mitre_techniques=['T1486'],
        recommendations=['Disconnect network', 'Restore from backup']
    )
    
    time.sleep(0.1)
    
    alert2 = alert_system.create_alert(
        title="Suspicious PowerShell Execution",
        description="PowerShell with encoded command detected",
        severity=AlertSeverity.HIGH,
        category="process",
        source="process_monitor",
        context={'process': 'powershell.exe', 'cmdline': '-encodedcommand ...'},
        mitre_techniques=['T1059.001'],
        recommendations=['Investigate process', 'Check command history']
    )
    
    time.sleep(0.1)
    
    # Try to create duplicate (should be suppressed)
    alert_system.create_alert(
        title="Suspicious PowerShell Execution",
        description="PowerShell with encoded command detected",
        severity=AlertSeverity.HIGH,
        category="process",
        source="process_monitor"
    )
    
    # Acknowledge alert
    print(f"\nAcknowledging alert: {alert1.alert_id}")
    alert_system.acknowledge_alert(alert1.alert_id, "admin")
    
    # Get correlated alerts
    correlated = alert_system.get_correlated_alerts(alert2.alert_id)
    print(f"\nCorrelated alerts for {alert2.alert_id}: {len(correlated)}")
    
    # Get unacknowledged
    unack = alert_system.get_unacknowledged_alerts()
    print(f"\nUnacknowledged alerts: {len(unack)}")
    
    # Statistics
    print("\n" + "="*50)
    stats = alert_system.get_statistics()
    print("Statistics:")
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for k, v in value.items():
                print(f"    {k}: {v}")
        else:
            print(f"  {key}: {value}")
    
    # Generate report
    print("\n" + alert_system.generate_report(hours=24))
    
    print("\n✅ Alert system ready!")