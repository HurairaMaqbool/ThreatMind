"""Tests for SQLite migrations."""
import os
import sqlite3
import tempfile
import unittest
import unittest.mock as mock

from memory.migrations import migrate_legacy_platforms, LEGACY_TABLE_PLATFORMS


class TestMigrations(unittest.TestCase):
    def test_legacy_platform_remapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "test.db")
            conn = sqlite3.connect(db_path)
            conn.execute(
                """
                CREATE TABLE generated_queries (
                    id INTEGER PRIMARY KEY,
                    platform TEXT
                )
            """
            )
            conn.execute(
                "INSERT INTO generated_queries (platform) VALUES ('DeviceProcessEvents')"
            )
            conn.execute(
                "INSERT INTO generated_queries (platform) VALUES ('sentinel')"
            )
            conn.commit()

            with mock.patch("memory.migrations.DB_PATH", db_path):
                fixed = migrate_legacy_platforms()
            self.assertEqual(fixed, 1)

            row = conn.execute("SELECT platform FROM generated_queries WHERE id=1").fetchone()
            self.assertEqual(row[0], "sentinel")
            conn.close()

    def test_all_legacy_names_known(self):
        self.assertIn("DeviceProcessEvents", LEGACY_TABLE_PLATFORMS)


if __name__ == "__main__":
    unittest.main()
