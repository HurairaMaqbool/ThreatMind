import sqlite3
import os
import re

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'autothreat.db')
if os.path.exists(DB_PATH):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Only delete mock rows: threat_1 through threat_99 (numeric suffix only)
    # Real pipeline rows use threat_ + 8-char hex UUID (e.g. threat_9211257f)
    c.execute("SELECT id, threat_id FROM generated_queries")
    all_rows = c.fetchall()
    mock_ids = [
        row[0] for row in all_rows
        if re.match(r'^threat_\d{1,2}$', row[1] or '')
    ]
    if mock_ids:
        placeholders = ','.join('?' * len(mock_ids))
        c.execute(f"DELETE FROM generated_queries WHERE id IN ({placeholders})", mock_ids)
        conn.commit()
        print(f"Mock data cleared: {len(mock_ids)} rows removed.")
    else:
        print("No mock data found to clear.")
    conn.close()
