#!/usr/bin/env python3
"""Run database migrations and report results."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from memory.sqlite_client import init_db
from memory.migrations import run_all_migrations


def main():
    print("Running AutoThreat database migrations...")
    init_db()
    result = run_all_migrations()
    print(f"  Platform rows fixed: {result['platform_rows_fixed']}")
    print(f"  Indexes: {result['indexes']}")
    print("Migration complete.")


if __name__ == "__main__":
    main()
