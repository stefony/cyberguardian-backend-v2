import sys
sys.path.insert(0, '.')

from database.db import get_threats

threats = get_threats()
for threat in threats:
    print(f"ID: {threat['id']}, Type: {threat['threat_type']}")
    print(f"Keys: {threat.keys()}")
    print(f"Confidence: {threat.get('confidence_score', 'MISSING')}")
    print("---")