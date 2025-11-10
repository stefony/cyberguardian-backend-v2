"""
CyberGuardian AI - MITRE ATT&CK Seed Data
Populate database with MITRE ATT&CK framework
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from database import db

def seed_mitre_data():
    """
    Seed MITRE ATT&CK framework data
    
    This is a subset of the MITRE ATT&CK framework focused on common techniques.
    Full framework has 190+ techniques, we're including the most common ones.
    """
    
    print("🔧 Seeding MITRE ATT&CK data...")
    
    # ============================================
    # TACTICS (12 core tactics in MITRE ATT&CK)
    # ============================================
    
    tactics = [
        {
            "tactic_id": "TA0001",
            "name": "Initial Access",
            "description": "The adversary is trying to get into your network.",
            "url": "https://attack.mitre.org/tactics/TA0001"
        },
        {
            "tactic_id": "TA0002",
            "name": "Execution",
            "description": "The adversary is trying to run malicious code.",
            "url": "https://attack.mitre.org/tactics/TA0002"
        },
        {
            "tactic_id": "TA0003",
            "name": "Persistence",
            "description": "The adversary is trying to maintain their foothold.",
            "url": "https://attack.mitre.org/tactics/TA0003"
        },
        {
            "tactic_id": "TA0004",
            "name": "Privilege Escalation",
            "description": "The adversary is trying to gain higher-level permissions.",
            "url": "https://attack.mitre.org/tactics/TA0004"
        },
        {
            "tactic_id": "TA0005",
            "name": "Defense Evasion",
            "description": "The adversary is trying to avoid being detected.",
            "url": "https://attack.mitre.org/tactics/TA0005"
        },
        {
            "tactic_id": "TA0006",
            "name": "Credential Access",
            "description": "The adversary is trying to steal account names and passwords.",
            "url": "https://attack.mitre.org/tactics/TA0006"
        },
        {
            "tactic_id": "TA0007",
            "name": "Discovery",
            "description": "The adversary is trying to figure out your environment.",
            "url": "https://attack.mitre.org/tactics/TA0007"
        },
        {
            "tactic_id": "TA0008",
            "name": "Lateral Movement",
            "description": "The adversary is trying to move through your environment.",
            "url": "https://attack.mitre.org/tactics/TA0008"
        },
        {
            "tactic_id": "TA0009",
            "name": "Collection",
            "description": "The adversary is trying to gather data of interest.",
            "url": "https://attack.mitre.org/tactics/TA0009"
        },
        {
            "tactic_id": "TA0010",
            "name": "Exfiltration",
            "description": "The adversary is trying to steal data.",
            "url": "https://attack.mitre.org/tactics/TA0010"
        },
        {
            "tactic_id": "TA0011",
            "name": "Command and Control",
            "description": "The adversary is trying to communicate with compromised systems.",
            "url": "https://attack.mitre.org/tactics/TA0011"
        },
        {
            "tactic_id": "TA0040",
            "name": "Impact",
            "description": "The adversary is trying to manipulate, interrupt, or destroy systems and data.",
            "url": "https://attack.mitre.org/tactics/TA0040"
        }
    ]
    
    print(f"Inserting {len(tactics)} tactics...")
    
    tactics_added = 0
    for tactic in tactics:
        try:
            result = db.add_mitre_tactic(**tactic)
            if result > 0:
                tactics_added += 1
        except Exception as e:
            print(f"⚠️ Error inserting tactic {tactic['tactic_id']}: {e}")
    
    print(f"✅ Added {tactics_added} tactics")
    
    # ============================================
    # TECHNIQUES (Top 35 most common techniques)
    # ============================================
    
    techniques = [
        # Initial Access
        {"technique_id": "T1566", "name": "Phishing", "tactic": "TA0001", 
         "description": "Adversaries send phishing messages to gain access.",
         "platforms": ["Windows", "macOS", "Linux", "Office 365", "SaaS"],
         "url": "https://attack.mitre.org/techniques/T1566"},
        
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "TA0001",
         "description": "Adversaries exploit software vulnerabilities in public-facing applications.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1190"},
        
        {"technique_id": "T1133", "name": "External Remote Services", "tactic": "TA0001",
         "description": "Adversaries leverage external-facing remote services to gain access.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1133"},
        
        # Execution
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "TA0002",
         "description": "Adversaries abuse command and scripting interpreters to execute commands.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1059"},
        
        {"technique_id": "T1203", "name": "Exploitation for Client Execution", "tactic": "TA0002",
         "description": "Adversaries exploit software vulnerabilities to execute code.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1203"},
        
        {"technique_id": "T1204", "name": "User Execution", "tactic": "TA0002",
         "description": "Adversaries rely on user actions to execute malicious code.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1204"},
        
        # Persistence
        {"technique_id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "TA0003",
         "description": "Adversaries configure system settings to execute at boot/login.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1547"},
        
        {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactic": "TA0003",
         "description": "Adversaries schedule code execution on remote or local systems.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1053"},
        
        {"technique_id": "T1543", "name": "Create or Modify System Process", "tactic": "TA0003",
         "description": "Adversaries create or modify system-level processes.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1543"},
        
        # Privilege Escalation
        {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "TA0004",
         "description": "Adversaries exploit vulnerabilities to elevate privileges.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1068"},
        
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "TA0004",
         "description": "Adversaries use valid accounts to maintain access.",
         "platforms": ["Windows", "macOS", "Linux", "Cloud"],
         "url": "https://attack.mitre.org/techniques/T1078"},
        
        # Defense Evasion
        {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "TA0005",
         "description": "Adversaries obfuscate files to hide malicious content.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1027"},
        
        {"technique_id": "T1055", "name": "Process Injection", "tactic": "TA0005",
         "description": "Adversaries inject code into processes to evade detection.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1055"},
        
        {"technique_id": "T1070", "name": "Indicator Removal", "tactic": "TA0005",
         "description": "Adversaries delete or modify artifacts to remove evidence.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1070"},
        
        {"technique_id": "T1562", "name": "Impair Defenses", "tactic": "TA0005",
         "description": "Adversaries disable security tools to avoid detection.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1562"},
        
        # Credential Access
        {"technique_id": "T1110", "name": "Brute Force", "tactic": "TA0006",
         "description": "Adversaries use trial and error to guess credentials.",
         "platforms": ["Windows", "macOS", "Linux", "Cloud"],
         "url": "https://attack.mitre.org/techniques/T1110"},
        
        {"technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "TA0006",
         "description": "Adversaries dump credentials from the operating system.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1003"},
        
        {"technique_id": "T1056", "name": "Input Capture", "tactic": "TA0006",
         "description": "Adversaries capture user input to steal credentials.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1056"},
        
        # Discovery
        {"technique_id": "T1083", "name": "File and Directory Discovery", "tactic": "TA0007",
         "description": "Adversaries enumerate files and directories.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1083"},
        
        {"technique_id": "T1082", "name": "System Information Discovery", "tactic": "TA0007",
         "description": "Adversaries gather system information.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1082"},
        
        {"technique_id": "T1018", "name": "Remote System Discovery", "tactic": "TA0007",
         "description": "Adversaries discover remote systems on the network.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1018"},
        
        # Lateral Movement
        {"technique_id": "T1021", "name": "Remote Services", "tactic": "TA0008",
         "description": "Adversaries use remote services to move laterally.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1021"},
        
        {"technique_id": "T1570", "name": "Lateral Tool Transfer", "tactic": "TA0008",
         "description": "Adversaries transfer tools between systems.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1570"},
        
        # Collection
        {"technique_id": "T1005", "name": "Data from Local System", "tactic": "TA0009",
         "description": "Adversaries collect data from local file systems.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1005"},
        
        {"technique_id": "T1114", "name": "Email Collection", "tactic": "TA0009",
         "description": "Adversaries collect email data.",
         "platforms": ["Windows", "macOS", "Linux", "Office 365"],
         "url": "https://attack.mitre.org/techniques/T1114"},
        
        {"technique_id": "T1113", "name": "Screen Capture", "tactic": "TA0009",
         "description": "Adversaries take screenshots.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1113"},
        
        # Exfiltration
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "TA0010",
         "description": "Adversaries steal data over their C2 channel.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1041"},
        
        {"technique_id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "TA0010",
         "description": "Adversaries exfiltrate data to cloud services.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1567"},
        
        # Command and Control
        {"technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "TA0011",
         "description": "Adversaries communicate using application layer protocols.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1071"},
        
        {"technique_id": "T1090", "name": "Proxy", "tactic": "TA0011",
         "description": "Adversaries use proxies to relay network traffic.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1090"},
        
        {"technique_id": "T1573", "name": "Encrypted Channel", "tactic": "TA0011",
         "description": "Adversaries encrypt C2 communications.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1573"},
        
        # Impact
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "TA0040",
         "description": "Adversaries encrypt data to disrupt availability (ransomware).",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1486"},
        
        {"technique_id": "T1490", "name": "Inhibit System Recovery", "tactic": "TA0040",
         "description": "Adversaries delete backups to prevent recovery.",
         "platforms": ["Windows", "macOS", "Linux"],
         "url": "https://attack.mitre.org/techniques/T1490"},
        
        {"technique_id": "T1485", "name": "Data Destruction", "tactic": "TA0040",
         "description": "Adversaries destroy data to disrupt operations.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1485"},
        
        {"technique_id": "T1489", "name": "Service Stop", "tactic": "TA0040",
         "description": "Adversaries stop services to disrupt operations.",
         "platforms": ["Windows", "Linux", "macOS"],
         "url": "https://attack.mitre.org/techniques/T1489"}
    ]
    
    print(f"Inserting {len(techniques)} techniques...")
    
    techniques_added = 0
    for tech in techniques:
        try:
            tactic = tech.pop("tactic")
            result = db.add_mitre_technique(tactic_id=tactic, **tech)
            if result > 0:
                techniques_added += 1
        except Exception as e:
            print(f"⚠️ Error inserting technique {tech.get('technique_id')}: {e}")
    
    print(f"✅ Added {techniques_added} techniques")
    
    print(f"\n✅ MITRE ATT&CK data seeded successfully!")
    print(f"   - {tactics_added}/{len(tactics)} tactics")
    print(f"   - {techniques_added}/{len(techniques)} techniques")


if __name__ == "__main__":
    seed_mitre_data()
    