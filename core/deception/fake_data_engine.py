"""
CyberGuardian AI - Fake Data Engine
Realistic Deception Data Generator

Generates believable fake data for honeypots:
- Credentials (usernames, passwords, API keys)
- Personal data (names, emails, phone numbers)
- Financial data (credit cards, bank accounts)
- Network data (IPs, domains, URLs)
- Database records
- Documents

Security Knowledge Applied:
- Data masking techniques
- Honeytokens
- Believable decoys
- Social engineering psychology
- Attacker expectations
"""

import logging
import random
import string
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FakeDataEngine:
    """
    Generates realistic fake data for honeypots.
    Data looks legitimate but is completely fake.
    """
    
    # Data pools for generation
    FIRST_NAMES = [
        'John', 'Jane', 'Michael', 'Emily', 'David', 'Sarah',
        'Robert', 'Jennifer', 'William', 'Jessica', 'James', 'Ashley',
        'Thomas', 'Lisa', 'Daniel', 'Amanda', 'Matthew', 'Melissa'
    ]
    
    LAST_NAMES = [
        'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia',
        'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez',
        'Wilson', 'Anderson', 'Thomas', 'Taylor', 'Moore', 'Jackson'
    ]
    
    DEPARTMENTS = [
        'Engineering', 'Sales', 'Marketing', 'Finance', 'HR',
        'Operations', 'IT', 'Customer Support', 'Legal', 'R&D'
    ]
    
    JOB_TITLES = [
        'Software Engineer', 'Senior Developer', 'Product Manager',
        'Data Analyst', 'DevOps Engineer', 'QA Engineer',
        'Marketing Manager', 'Sales Representative', 'HR Manager',
        'Financial Analyst', 'System Administrator', 'Security Analyst'
    ]
    
    DOMAINS = [
        'company.com', 'techcorp.com', 'business.net', 'enterprise.com',
        'services.io', 'solutions.com', 'systems.net', 'corp.com'
    ]
    
    STREET_NAMES = [
        'Main St', 'Oak Ave', 'Park Rd', 'Elm St', 'Washington Blvd',
        'Maple Dr', 'Cedar Ln', 'Pine St', 'Market St', 'Broadway'
    ]
    
    CITIES = [
        'New York', 'Los Angeles', 'Chicago', 'Houston', 'Phoenix',
        'Philadelphia', 'San Antonio', 'San Diego', 'Dallas', 'San Jose',
        'Austin', 'Seattle', 'Denver', 'Boston', 'Portland'
    ]
    
    STATES = [
        'CA', 'NY', 'TX', 'FL', 'IL', 'PA', 'OH', 'GA', 'NC', 'MI',
        'NJ', 'VA', 'WA', 'AZ', 'MA', 'TN', 'IN', 'MO', 'MD', 'WI'
    ]
    
    def __init__(self):
        """Initialize fake data engine"""
        self.generated_count = 0
        logger.info("FakeDataEngine initialized")
    
    # ==================== CREDENTIALS ====================
    
    def generate_username(self, style: str = "name_based") -> str:
        """
        Generate fake username.
        
        Args:
            style: 'name_based', 'id_based', or 'random'
            
        Returns:
            Fake username
        """
        if style == "name_based":
            first = random.choice(self.FIRST_NAMES).lower()
            last = random.choice(self.LAST_NAMES).lower()
            
            patterns = [
                f"{first}.{last}",
                f"{first}{last}",
                f"{first[0]}{last}",
                f"{first}_{last}",
                f"{last}{first[0]}"
            ]
            return random.choice(patterns)
        
        elif style == "id_based":
            return f"user{random.randint(1000, 9999)}"
        
        else:  # random
            length = random.randint(6, 12)
            return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def generate_password(self, strength: str = "medium") -> str:
        """
        Generate fake password.
        
        Args:
            strength: 'weak', 'medium', or 'strong'
            
        Returns:
            Fake password
        """
        if strength == "weak":
            # Common weak passwords
            weak_passwords = [
                'password123', 'admin123', 'welcome1', 'qwerty123',
                'letmein', '123456789', 'password1', 'admin2024'
            ]
            return random.choice(weak_passwords)
        
        elif strength == "medium":
            # Realistic medium-strength passwords
            words = ['Password', 'Admin', 'Welcome', 'Secure', 'Access']
            word = random.choice(words)
            number = random.randint(1, 9999)
            special = random.choice(['!', '@', '#', '$'])
            return f"{word}{number}{special}"
        
        else:  # strong
            # Complex passwords
            length = random.randint(12, 16)
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            password = ''.join(random.choices(chars, k=length))
            # Ensure it has at least one of each type
            if not any(c.isupper() for c in password):
                password = password[:1].upper() + password[1:]
            if not any(c in "!@#$%^&*" for c in password):
                password += random.choice("!@#$%^&*")
            return password
    
    def generate_email(self, domain: str = None) -> str:
        """Generate fake email address"""
        username = self.generate_username("name_based")
        domain = domain or random.choice(self.DOMAINS)
        return f"{username}@{domain}"
    
    def generate_api_key(self, prefix: str = "sk_live") -> str:
        """Generate fake API key"""
        random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        return f"{prefix}_{random_part}"
    
    def generate_jwt_token(self) -> str:
        """Generate fake JWT token"""
        # Fake JWT structure: header.payload.signature
        header = self._base64_encode('{"alg":"HS256","typ":"JWT"}')
        payload_data = {
            "sub": str(random.randint(1000, 9999)),
            "name": f"{random.choice(self.FIRST_NAMES)} {random.choice(self.LAST_NAMES)}",
            "iat": int(datetime.now().timestamp())
        }
        payload = self._base64_encode(json.dumps(payload_data))
        signature = ''.join(random.choices(string.ascii_letters + string.digits + '-_', k=43))
        return f"{header}.{payload}.{signature}"
    
    def _base64_encode(self, text: str) -> str:
        """Simple base64-like encoding for fake tokens"""
        import base64
        return base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')
    
    # ==================== PERSONAL DATA ====================
    
    def generate_person(self) -> Dict:
        """Generate complete fake person data"""
        first_name = random.choice(self.FIRST_NAMES)
        last_name = random.choice(self.LAST_NAMES)
        
        return {
            'first_name': first_name,
            'last_name': last_name,
            'full_name': f"{first_name} {last_name}",
            'email': self.generate_email(),
            'username': self.generate_username("name_based"),
            'phone': self.generate_phone_number(),
            'ssn': self.generate_ssn(),
            'date_of_birth': self.generate_date_of_birth(),
            'address': self.generate_address()
        }
    
    def generate_phone_number(self, format: str = "US") -> str:
        """Generate fake phone number"""
        if format == "US":
            area = random.randint(200, 999)
            prefix = random.randint(200, 999)
            line = random.randint(1000, 9999)
            return f"+1-{area}-{prefix}-{line}"
        else:
            return f"+1-555-{random.randint(1000, 9999)}"
    
    def generate_ssn(self) -> str:
        """Generate fake SSN (US Social Security Number)"""
        # Use fake range to avoid real SSNs
        area = random.randint(900, 999)  # Invalid area numbers
        group = random.randint(10, 99)
        serial = random.randint(1000, 9999)
        return f"{area}-{group}-{serial}"
    
    def generate_date_of_birth(self) -> str:
        """Generate fake date of birth"""
        year = random.randint(1960, 2000)
        month = random.randint(1, 12)
        day = random.randint(1, 28)
        return f"{year}-{month:02d}-{day:02d}"
    
    def generate_address(self) -> Dict:
        """Generate fake address"""
        return {
            'street': f"{random.randint(100, 9999)} {random.choice(self.STREET_NAMES)}",
            'city': random.choice(self.CITIES),
            'state': random.choice(self.STATES),
            'zip': f"{random.randint(10000, 99999)}",
            'country': 'USA'
        }
    
    # ==================== FINANCIAL DATA ====================
    
    def generate_credit_card(self, card_type: str = "visa") -> Dict:
        """Generate fake credit card"""
        if card_type == "visa":
            number = f"4{random.randint(100, 999)}{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
        elif card_type == "mastercard":
            number = f"5{random.randint(100, 999)}{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
        else:
            number = f"{random.randint(1000, 9999)}{random.randint(1000, 9999)}{random.randint(1000, 9999)}"
        
        # Add spaces for readability
        number_formatted = ' '.join([number[i:i+4] for i in range(0, len(number), 4)])
        
        exp_month = random.randint(1, 12)
        exp_year = random.randint(2025, 2030)
        cvv = random.randint(100, 999)
        
        return {
            'number': number_formatted,
            'expiry': f"{exp_month:02d}/{exp_year}",
            'cvv': str(cvv),
            'type': card_type,
            'holder': f"{random.choice(self.FIRST_NAMES)} {random.choice(self.LAST_NAMES)}"
        }
    
    def generate_bank_account(self) -> Dict:
        """Generate fake bank account"""
        routing = random.randint(100000000, 999999999)
        account = random.randint(1000000000, 9999999999)
        
        return {
            'routing_number': str(routing),
            'account_number': str(account),
            'account_type': random.choice(['checking', 'savings']),
            'bank_name': random.choice(['Chase', 'Bank of America', 'Wells Fargo', 'Citibank'])
        }
    
    def generate_transaction(self) -> Dict:
        """Generate fake financial transaction"""
        return {
            'transaction_id': f"TXN{random.randint(100000, 999999)}",
            'date': (datetime.now() - timedelta(days=random.randint(0, 365))).isoformat(),
            'amount': round(random.uniform(10.00, 5000.00), 2),
            'merchant': random.choice(['Amazon', 'Walmart', 'Target', 'Starbucks', 'Apple']),
            'category': random.choice(['Shopping', 'Food', 'Entertainment', 'Travel', 'Bills']),
            'status': random.choice(['completed', 'pending', 'authorized'])
        }
    
    # ==================== COMPANY DATA ====================
    
    def generate_employee(self) -> Dict:
        """Generate fake employee record"""
        person = self.generate_person()
        
        return {
            'employee_id': f"EMP{random.randint(1000, 9999)}",
            'first_name': person['first_name'],
            'last_name': person['last_name'],
            'email': person['email'],
            'department': random.choice(self.DEPARTMENTS),
            'job_title': random.choice(self.JOB_TITLES),
            'salary': random.randint(50000, 200000),
            'hire_date': (datetime.now() - timedelta(days=random.randint(30, 3650))).strftime("%Y-%m-%d"),
            'manager_id': f"EMP{random.randint(1000, 9999)}",
            'status': 'active'
        }
    
    def generate_department(self) -> Dict:
        """Generate fake department info"""
        return {
            'department_id': f"DEPT{random.randint(100, 999)}",
            'name': random.choice(self.DEPARTMENTS),
            'head': f"{random.choice(self.FIRST_NAMES)} {random.choice(self.LAST_NAMES)}",
            'budget': random.randint(100000, 5000000),
            'employee_count': random.randint(5, 100)
        }
    
    # ==================== NETWORK DATA ====================
    
    def generate_ip_address(self, ip_type: str = "public") -> str:
        """Generate fake IP address"""
        if ip_type == "public":
            # Avoid private ranges
            octet1 = random.choice([int(x) for x in range(1, 255) if x not in [10, 127, 172, 192]])
            return f"{octet1}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        elif ip_type == "private":
            # Use private ranges
            ranges = [
                (10, random.randint(0, 255), random.randint(0, 255)),
                (192, 168, random.randint(0, 255)),
                (172, random.randint(16, 31), random.randint(0, 255))
            ]
            octets = random.choice(ranges)
            return f"{octets[0]}.{octets[1]}.{octets[2]}.{random.randint(1, 254)}"
        
        else:  # local
            return f"127.0.0.{random.randint(1, 254)}"
    
    def generate_domain(self) -> str:
        """Generate fake domain name"""
        words = ['tech', 'data', 'cloud', 'cyber', 'info', 'global', 'smart', 'digital']
        word = random.choice(words)
        number = random.randint(1, 999) if random.random() > 0.7 else ""
        tld = random.choice(['.com', '.net', '.io', '.org', '.co'])
        return f"{word}{number}{tld}"
    
    def generate_url(self, protocol: str = "https") -> str:
        """Generate fake URL"""
        domain = self.generate_domain()
        paths = ['api', 'admin', 'dashboard', 'login', 'users', 'data']
        path = '/'.join(random.sample(paths, random.randint(1, 3)))
        return f"{protocol}://{domain}/{path}"
    
    def generate_mac_address(self) -> str:
        """Generate fake MAC address"""
        mac = [random.randint(0x00, 0xff) for _ in range(6)]
        return ':'.join(f'{x:02x}' for x in mac)
    
    # ==================== DATABASE RECORDS ====================
    
    def generate_user_record(self) -> Dict:
        """Generate fake database user record"""
        person = self.generate_person()
        
        # Generate password hash (fake but realistic-looking)
        password = self.generate_password("medium")
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        return {
            'id': random.randint(1, 100000),
            'username': person['username'],
            'email': person['email'],
            'password_hash': f"$2b$12${password_hash[:50]}",
            'first_name': person['first_name'],
            'last_name': person['last_name'],
            'created_at': (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
            'last_login': datetime.now().isoformat(),
            'is_active': True,
            'role': random.choice(['user', 'admin', 'moderator'])
        }
    
    def generate_session_token(self) -> str:
        """Generate fake session token"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=64))
    
    # ==================== BATCH GENERATION ====================
    
    def generate_batch_users(self, count: int) -> List[Dict]:
        """Generate multiple fake users"""
        return [self.generate_user_record() for _ in range(count)]
    
    def generate_batch_employees(self, count: int) -> List[Dict]:
        """Generate multiple fake employees"""
        return [self.generate_employee() for _ in range(count)]
    
    def generate_batch_transactions(self, count: int) -> List[Dict]:
        """Generate multiple fake transactions"""
        return [self.generate_transaction() for _ in range(count)]
    
    # ==================== EXPORT FUNCTIONS ====================
    
    def generate_csv_content(self, record_type: str, count: int) -> str:
        """
        Generate CSV content with fake data.
        
        Args:
            record_type: 'users', 'employees', 'transactions'
            count: Number of records
            
        Returns:
            CSV content as string
        """
        if record_type == 'users':
            records = self.generate_batch_users(count)
            headers = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 'created_at']
        elif record_type == 'employees':
            records = self.generate_batch_employees(count)
            headers = ['employee_id', 'first_name', 'last_name', 'email', 'department', 'job_title', 'salary']
        elif record_type == 'transactions':
            records = self.generate_batch_transactions(count)
            headers = ['transaction_id', 'date', 'amount', 'merchant', 'category', 'status']
        else:
            return ""
        
        # Build CSV
        csv_lines = [','.join(headers)]
        for record in records:
            values = [str(record.get(h, '')) for h in headers]
            csv_lines.append(','.join(values))
        
        return '\n'.join(csv_lines)
    
    def generate_json_content(self, record_type: str, count: int) -> str:
        """Generate JSON content with fake data"""
        if record_type == 'users':
            records = self.generate_batch_users(count)
        elif record_type == 'employees':
            records = self.generate_batch_employees(count)
        elif record_type == 'transactions':
            records = self.generate_batch_transactions(count)
        else:
            records = []
        
        return json.dumps(records, indent=2)


def create_fake_data_engine() -> FakeDataEngine:
    """Factory function to create FakeDataEngine instance"""
    return FakeDataEngine()


# Testing
if __name__ == "__main__":
    print("🎭 CyberGuardian - Fake Data Engine Test\n")
    
    engine = create_fake_data_engine()
    
    print("Test 1: Generate credentials")
    print(f"   Username: {engine.generate_username('name_based')}")
    print(f"   Password: {engine.generate_password('medium')}")
    print(f"   Email: {engine.generate_email()}")
    print(f"   API Key: {engine.generate_api_key()}")
    
    print("\nTest 2: Generate person")
    person = engine.generate_person()
    print(f"   Name: {person['full_name']}")
    print(f"   Email: {person['email']}")
    print(f"   Phone: {person['phone']}")
    print(f"   Address: {person['address']['street']}, {person['address']['city']}")
    
    print("\nTest 3: Generate financial data")
    card = engine.generate_credit_card()
    print(f"   Card: {card['number']}")
    print(f"   Expiry: {card['expiry']} CVV: {card['cvv']}")
    
    account = engine.generate_bank_account()
    print(f"   Account: {account['account_number']} (Routing: {account['routing_number']})")
    
    print("\nTest 4: Generate employee")
    employee = engine.generate_employee()
    print(f"   ID: {employee['employee_id']}")
    print(f"   Name: {employee['first_name']} {employee['last_name']}")
    print(f"   Title: {employee['job_title']} ({employee['department']})")
    print(f"   Salary: ${employee['salary']:,}")
    
    print("\nTest 5: Generate network data")
    print(f"   Public IP: {engine.generate_ip_address('public')}")
    print(f"   Private IP: {engine.generate_ip_address('private')}")
    print(f"   Domain: {engine.generate_domain()}")
    print(f"   URL: {engine.generate_url()}")
    
    print("\nTest 6: Batch generation")
    users = engine.generate_batch_users(3)
    print(f"   Generated {len(users)} fake users:")
    for user in users:
        print(f"      - {user['username']} ({user['email']})")
    
    print("\n✅ Fake Data Engine test complete!")
    print("\n⚠️  All data is completely fake and for deception purposes only!")