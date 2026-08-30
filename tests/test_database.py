import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from codeshield.database import Database


class DatabaseTests(unittest.TestCase):
    def test_initialize_is_repeatable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "test.db")
            database.initialize()
            database.initialize()

            with closing(database.connect()) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }

            self.assertTrue({"scan_history", "scan_results", "custom_rules", "whitelist"} <= tables)

    def test_dashboard_starts_at_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "test.db")
            database.initialize()

            self.assertEqual(
                database.dashboard_counts(),
                {"scans": 0, "files": 0, "findings": 0, "critical": 0},
            )


if __name__ == "__main__":
    unittest.main()
