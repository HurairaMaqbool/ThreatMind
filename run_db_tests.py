import sqlite3
import os
import re

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "autothreat.db")
MOCK_RE = re.compile(r"^threat_\d{1,2}$")

if not os.path.exists(DB_PATH):
    print(f"Database not found at {DB_PATH}")
    raise SystemExit(1)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute("SELECT COUNT(*) FROM generated_queries")
print("Total rows:", c.fetchone()[0])

c.execute("SELECT DISTINCT severity FROM generated_queries")
print("Severities:", [r[0] for r in c.fetchall()])

c.execute("SELECT DISTINCT tier FROM generated_queries")
print("Tiers:", [r[0] for r in c.fetchall()])

c.execute("SELECT DISTINCT platform FROM generated_queries")
print("Platforms:", [r[0] for r in c.fetchall()])

c.execute("SELECT COUNT(*) FROM generated_queries WHERE query_text IS NULL OR query_text = ''")
print("Null query_text:", c.fetchone()[0])

c.execute("SELECT COUNT(*) FROM generated_queries WHERE threat_name IS NULL OR threat_name = ''")
print("Null threat_name:", c.fetchone()[0])

c.execute("SELECT COUNT(*) FROM generated_queries WHERE query_text NOT LIKE '%|%' AND platform = 'sentinel'")
print("Sentinel queries missing pipe |:", c.fetchone()[0])

c.execute(
    "SELECT COUNT(*) FROM generated_queries WHERE query_text NOT LIKE '%TimeGenerated%' AND platform = 'sentinel'"
)
print("Sentinel queries missing TimeGenerated:", c.fetchone()[0])

for col in ["CommandLine", "ParentProcess", " Hash ", " User "]:
    c.execute("SELECT COUNT(*) FROM generated_queries WHERE query_text LIKE ?", (f"%{col}%",))
    print(f"Wrong column [{col.strip()}]:", c.fetchone()[0])

c.execute("SELECT angle_id, query_text, platform FROM generated_queries LIMIT 5")
rows = c.fetchall()
tables = [
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceLogonEvents",
    "IdentityLogonEvents",
    "DeviceEvents",
    "SecurityEvent",
    "AzureActivity",
]
bad_table_count = 0
for angle_id, qt, platform in rows:
    if platform == "sentinel" and not any(t in (qt or "") for t in tables):
        bad_table_count += 1
        print(f"WARN: No known MDE/Sentinel table in query for {angle_id}")
print(f"Sentinel queries missing known table (of first 5 checked): {bad_table_count}")

c.execute("SELECT threat_id FROM generated_queries")
all_ids = [r[0] for r in c.fetchall()]
mock_count = sum(1 for tid in all_ids if MOCK_RE.match(str(tid)))
real_count = len(all_ids) - mock_count
print(f"Mock rows (threat_1..threat_99): {mock_count}")
print(f"Real pipeline rows: {real_count}")

if real_count > 0:
    c.execute("SELECT DISTINCT threat_id, threat_name FROM generated_queries")
    for tid, tname in c.fetchall():
        if not MOCK_RE.match(str(tid)):
            print(f"  [REAL] {tid}: {str(tname)[:60]}")

conn.close()
print("\nAll DB checks complete.")
