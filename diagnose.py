import sqlite3
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from memory.sqlite_client import init_db
from memory.migrations import run_all_migrations

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "autothreat.db")


def main():
    print(f"\n=== AutoThreat Diagnostics ===")
    print(f"DB: {DB_PATH}\n")

    init_db()
    mig = run_all_migrations()
    if mig["platform_rows_fixed"]:
        print(f"[MIGRATE] Fixed {mig['platform_rows_fixed']} legacy platform rows → sentinel")

    if not os.path.exists(DB_PATH):
        print("NO DATABASE — pipeline has not written data yet.")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    tables = [row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    print(f"Tables: {tables}")

    if "generated_queries" not in tables:
        print("generated_queries table missing.")
        conn.close()
        return

    c.execute("SELECT COUNT(*) FROM generated_queries")
    total = c.fetchone()[0]
    print(f"Total rows: {total}")

    mock_re = re.compile(r"^threat_\d{1,2}$")
    c.execute("SELECT threat_id FROM generated_queries")
    all_ids = [r[0] for r in c.fetchall()]
    mock_count = sum(1 for tid in all_ids if mock_re.match(str(tid)))
    print(f"Real rows: {len(all_ids) - mock_count} | Mock rows: {mock_count}")

    c.execute("SELECT DISTINCT platform FROM generated_queries")
    print(f"Platforms: {[r[0] for r in c.fetchall()]}")

    if total > 0:
        c.execute(
            "SELECT threat_id, threat_name, platform, severity, created_at "
            "FROM generated_queries ORDER BY created_at DESC LIMIT 5"
        )
        print("\nLatest entries:")
        for row in c.fetchall():
            print(f"  {row}")

    conn.close()

    from utils.health import full_health
    print(f"\nHealth: {full_health(deep=False)['status']}")


if __name__ == "__main__":
    main()
