import sqlite3
import datetime
import os
import random

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'autothreat.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def populate_mock_data():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS generated_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id TEXT,
            threat_name TEXT,
            angle_id TEXT,
            platform TEXT,
            technique TEXT,
            tier TEXT,
            severity TEXT,
            query_text TEXT,
            created_at TIMESTAMP
        )
    ''')
    
    threats = [
        ("T1059", "APT29 Cozy Bear Phishing", "CRITICAL"),
        ("T1003", "Diamond Sleet Credential Dumping", "HIGH"),
        ("T1566", "Commodity Emotet Campaign", "MEDIUM"),
        ("T1078", "Valid Accounts Abuse", "LOW")
    ]
    
    platforms = ["sentinel", "splunk", "qradar", "elastic", "crowdstrike", "wazuh", "sentinelone"]
    tiers = ["behavioral", "tool_artifact", "indicator"]
    
    now = datetime.datetime.now()
    
    for i in range(1, 100):
        t_tech, t_name, t_sev = random.choice(threats)
        p = random.choice(platforms)
        tr = random.choice(tiers)
        q_text = f"// Mock query for {t_name} on {p}\nsearch index=malware \"{t_tech}\""
        
        c.execute('''
            INSERT INTO generated_queries 
            (threat_id, threat_name, angle_id, platform, technique, tier, severity, query_text, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (f"threat_{i}", t_name, f"angle_{i}", p, t_tech, tr, t_sev, q_text, now))
        
    conn.commit()
    conn.close()
    print("Mock data successfully injected into SQLite!")

if __name__ == "__main__":
    populate_mock_data()
