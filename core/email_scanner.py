"""
CyberGuardian AI - Email & Phishing Scanner
Real IMAP-based email scanning and phishing detection
"""

import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging
from bs4 import BeautifulSoup
import os
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class EmailScanResult:
    """Email scan result"""
    email_id: str
    subject: str
    sender: str
    date: str
    is_phishing: bool
    phishing_score: float
    threat_level: str  # "safe", "suspicious", "dangerous"
    indicators: List[str]
    urls: List[str]
    attachments: List[str]
    recommendations: List[str]

class EmailScanner:
    """
    Real Email Scanner with Phishing Detection
    
    Features:
    - IMAP connection to any email provider
    - Email header analysis
    - URL extraction and validation
    - Phishing pattern detection
    - Suspicious sender detection
    - Attachment analysis
    """
    
    def __init__(self, server: str, port: int, username: str, password: str, use_ssl: bool = True):
        """
        Initialize email scanner
        
        Args:
            server: IMAP server (e.g., imap.gmail.com)
            port: IMAP port (e.g., 993 for SSL)
            username: Email address
            password: App password or password
            use_ssl: Use SSL/TLS
        """
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.connection = None
        
        # Phishing indicators
        self.phishing_keywords = [
            'verify', 'suspend', 'urgent', 'act now', 'confirm', 'security alert',
            'unusual activity', 'locked', 'limited time', 'click here', 'validate',
            'account verification', 'billing problem', 'payment failed', 'expire',
            'won', 'prize', 'congratulations', 'free', 'claim', 'bonus'
        ]
        
        self.suspicious_domains = [
            'tk', 'ml', 'ga', 'cf', 'gq',  # Free domains often used in phishing
        ]
        
        self.trusted_domains = [
            'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
            'icloud.com', 'hotmail.com'
        ]
    
    def connect(self) -> bool:
        """Connect to IMAP server"""
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.server, self.port)
            else:
                self.connection = imaplib.IMAP4(self.server, self.port)
            
            self.connection.login(self.username, self.password)
            logger.info(f"Connected to {self.server} as {self.username}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from IMAP server"""
        if self.connection:
            try:
                self.connection.logout()
                logger.info("Disconnected from IMAP server")
            except:
                pass
    
    def fetch_emails(self, folder: str = "INBOX", limit: int = 10) -> List[Dict]:
        """
        Fetch emails from specified folder
        
        Args:
            folder: Email folder (INBOX, Spam, etc.)
            limit: Maximum number of emails to fetch
        
        Returns:
            List of email data
        """
        if not self.connection:
            if not self.connect():
                return []
        
        try:
            self.connection.select(folder)
            
            # Search for all emails
            status, messages = self.connection.search(None, 'ALL')
            email_ids = messages[0].split()
            
            # Get latest emails
            email_ids = email_ids[-limit:]
            
            emails = []
            for email_id in reversed(email_ids):
                try:
                    email_data = self._fetch_email_by_id(email_id.decode())
                    if email_data:
                        emails.append(email_data)
                except Exception as e:
                    logger.error(f"Error fetching email {email_id}: {e}")
            
            return emails
        except Exception as e:
            logger.error(f"Error fetching emails: {e}")
            return []
    
    def _fetch_email_by_id(self, email_id: str) -> Optional[Dict]:
        """Fetch single email by ID"""
        try:
            status, msg_data = self.connection.fetch(email_id, '(RFC822)')
            
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    
                    # Decode subject
                    subject = self._decode_header(msg['Subject'])
                    
                    # Parse sender
                    sender = parseaddr(msg['From'])[1]
                    
                    # Get date
                    date = msg['Date']
                    
                    # Extract body
                    body = self._get_email_body(msg)
                    
                    # Extract URLs
                    urls = self._extract_urls(body)
                    
                    # Get attachments
                    attachments = self._get_attachments(msg)
                    
                    return {
                        'id': email_id,
                        'subject': subject,
                        'sender': sender,
                        'date': date,
                        'body': body,
                        'urls': urls,
                        'attachments': attachments
                    }
        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            return None
    
    def _decode_header(self, header: str) -> str:
        """Decode email header"""
        if not header:
            return ""
        
        decoded = decode_header(header)
        parts = []
        for content, encoding in decoded:
            if isinstance(content, bytes):
                parts.append(content.decode(encoding or 'utf-8', errors='ignore'))
            else:
                parts.append(content)
        return ' '.join(parts)
    
    def _get_email_body(self, msg) -> str:
        """Extract email body"""
        body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode(errors='ignore')
                    except:
                        pass
                elif content_type == "text/html":
                    try:
                        html = part.get_payload(decode=True).decode(errors='ignore')
                        soup = BeautifulSoup(html, 'html.parser')
                        body += soup.get_text()
                    except:
                        pass
        else:
            try:
                body = msg.get_payload(decode=True).decode(errors='ignore')
            except:
                body = str(msg.get_payload())
        
        return body
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))  # Remove duplicates
    
    def _get_attachments(self, msg) -> List[str]:
        """Get attachment filenames"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)
        
        return attachments
    
    def scan_email(self, email_data: Dict) -> EmailScanResult:
        """
        Scan email for phishing indicators
        
        Args:
            email_data: Email data dictionary
        
        Returns:
            EmailScanResult with phishing analysis
        """
        indicators = []
        phishing_score = 0.0
        
        subject = email_data.get('subject', '').lower()
        sender = email_data.get('sender', '').lower()
        body = email_data.get('body', '').lower()
        urls = email_data.get('urls', [])
        attachments = email_data.get('attachments', [])
        
        # Check phishing keywords in subject
        for keyword in self.phishing_keywords:
            if keyword in subject:
                phishing_score += 10
                indicators.append(f"Suspicious keyword in subject: '{keyword}'")
        
        # Check phishing keywords in body
        keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in body)
        if keyword_count > 3:
            phishing_score += 15
            indicators.append(f"Multiple phishing keywords found ({keyword_count})")
        
        # Check sender domain
        sender_domain = sender.split('@')[-1] if '@' in sender else ''
        
        if any(susp in sender_domain for susp in self.suspicious_domains):
            phishing_score += 20
            indicators.append(f"Suspicious sender domain: {sender_domain}")
        
        # Check for mismatched display name and email
        if sender_domain and sender_domain not in self.trusted_domains:
            phishing_score += 10
            indicators.append("Sender from non-trusted domain")
        
        # Check URLs
        suspicious_url_count = 0
        for url in urls:
            # Check for URL shorteners
            if any(short in url for short in ['bit.ly', 'tinyurl', 'goo.gl']):
                suspicious_url_count += 1
                indicators.append(f"URL shortener detected: {url}")
            
            # Check for IP addresses in URL
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                suspicious_url_count += 1
                indicators.append(f"IP address in URL: {url}")
        
        if suspicious_url_count > 0:
            phishing_score += suspicious_url_count * 15
        
        # Check for urgency/pressure tactics
        urgency_words = ['urgent', 'immediate', 'act now', 'limited time', 'expires']
        urgency_count = sum(1 for word in urgency_words if word in body or word in subject)
        if urgency_count >= 2:
            phishing_score += 10
            indicators.append("Urgency/pressure tactics detected")
        
        # Check for suspicious attachments
        dangerous_extensions = ['.exe', '.zip', '.rar', '.js', '.bat', '.cmd', '.scr']
        for attachment in attachments:
            if any(attachment.lower().endswith(ext) for ext in dangerous_extensions):
                phishing_score += 25
                indicators.append(f"Dangerous attachment: {attachment}")
        
        # Check for requests for personal info
        personal_info_requests = ['password', 'credit card', 'social security', 'ssn', 'account number']
        for request in personal_info_requests:
            if request in body:
                phishing_score += 20
                indicators.append(f"Requests personal information: {request}")
        
        # Determine threat level
        if phishing_score >= 50:
            threat_level = "dangerous"
            is_phishing = True
        elif phishing_score >= 25:
            threat_level = "suspicious"
            is_phishing = False
        else:
            threat_level = "safe"
            is_phishing = False
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_level, indicators)
        
        return EmailScanResult(
            email_id=email_data.get('id', ''),
            subject=email_data.get('subject', ''),
            sender=email_data.get('sender', ''),
            date=email_data.get('date', ''),
            is_phishing=is_phishing,
            phishing_score=min(phishing_score, 100),
            threat_level=threat_level,
            indicators=indicators,
            urls=urls,
            attachments=attachments,
            recommendations=recommendations
        )
    
    def _generate_recommendations(self, threat_level: str, indicators: List[str]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if threat_level == "dangerous":
            recommendations.append("⛔ DO NOT click any links in this email")
            recommendations.append("⛔ DO NOT open any attachments")
            recommendations.append("⛔ DO NOT reply to this email")
            recommendations.append("🗑️ Delete this email immediately")
            recommendations.append("📧 Report this email as phishing to your email provider")
        elif threat_level == "suspicious":
            recommendations.append("⚠️ Be cautious with this email")
            recommendations.append("🔍 Verify sender identity before taking action")
            recommendations.append("🔗 Do not click links unless verified")
            recommendations.append("📞 Contact sender through known channels if unsure")
        else:
            recommendations.append("✅ Email appears safe")
            recommendations.append("🔍 Still verify sender if requesting sensitive actions")
        
        return recommendations
    
    def scan_folder(self, folder: str = "INBOX", limit: int = 10) -> List[EmailScanResult]:
        """
        Scan multiple emails in a folder
        
        Args:
            folder: Email folder to scan
            limit: Maximum number of emails
        
        Returns:
            List of scan results
        """
        emails = self.fetch_emails(folder, limit)
        results = []
        
        for email_data in emails:
            try:
                result = self.scan_email(email_data)
                results.append(result)
            except Exception as e:
                logger.error(f"Error scanning email: {e}")
        
        return results


# Example usage and testing
if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    # Test configuration
    server = os.getenv("EMAIL_SERVER", "imap.gmail.com")
    port = int(os.getenv("EMAIL_PORT", 993))
    username = os.getenv("EMAIL_USERNAME", "")
    password = os.getenv("EMAIL_PASSWORD", "")
    
    if not username or not password:
        print("❌ Please set EMAIL_USERNAME and EMAIL_PASSWORD in .env file")
        exit(1)
    
    print("🔍 Testing Email Scanner...")
    print(f"📧 Connecting to {server}...")
    
    scanner = EmailScanner(server, port, username, password)
    
    if scanner.connect():
        print("✅ Connected successfully!")
        
        print("\n📬 Fetching latest 5 emails...")
        results = scanner.scan_folder(limit=5)
        
        print(f"\n📊 Scanned {len(results)} emails\n")
        
        for i, result in enumerate(results, 1):
            print(f"{'='*60}")
            print(f"Email #{i}")
            print(f"{'='*60}")
            print(f"From: {result.sender}")
            print(f"Subject: {result.subject}")
            print(f"Date: {result.date}")
            print(f"Threat Level: {result.threat_level.upper()}")
            print(f"Phishing Score: {result.phishing_score}/100")
            print(f"Is Phishing: {'⛔ YES' if result.is_phishing else '✅ NO'}")
            
            if result.indicators:
                print(f"\n⚠️ Indicators:")
                for indicator in result.indicators:
                    print(f"  - {indicator}")
            
            if result.urls:
                print(f"\n🔗 URLs found: {len(result.urls)}")
            
            if result.attachments:
                print(f"\n📎 Attachments: {', '.join(result.attachments)}")
            
            if result.recommendations:
                print(f"\n💡 Recommendations:")
                for rec in result.recommendations:
                    print(f"  {rec}")
            
            print()
        
        scanner.disconnect()
    else:
        print("❌ Failed to connect!")