#!/usr/bin/env python3
"""Pre-flight checks before running AutoThreat."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv

load_dotenv()


def main():
    print("=" * 50)
    print(" AutoThreat v3.0 — Pre-flight Check")
    print("=" * 50)

    ok = True

    if not os.getenv("GROQ_API_KEY") or os.getenv("GROQ_API_KEY", "").startswith("your_"):
        print("[FAIL] GROQ_API_KEY not configured in .env")
        ok = False
    else:
        print("[OK]   GROQ_API_KEY set")

    from utils.health import full_health
    from memory.sqlite_client import init_db
    from memory.migrations import run_all_migrations

    init_db()
    mig = run_all_migrations()
    if mig["platform_rows_fixed"]:
        print(f"[FIX]  Migrated {mig['platform_rows_fixed']} legacy platform rows → sentinel")

    health = full_health(deep=True)
    for name, check in health.get("checks", {}).items():
        status = "OK" if check.get("ok") else "FAIL"
        print(f"[{status}]  {name}: {check}")
        if not check.get("ok"):
            ok = False

    print("-" * 50)
    print(f"Overall: {'READY' if ok else 'NOT READY — fix issues above'}")
    print("=" * 50)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
