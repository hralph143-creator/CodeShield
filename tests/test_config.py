import json
import tempfile
import unittest
from pathlib import Path

from codeshield.config import AppConfig, ConfigStore


class ConfigStoreTests(unittest.TestCase):
    def test_creates_default_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory))
            config = store.load()

            self.assertEqual(config.max_file_size_mb, 5)
            self.assertTrue(store.path.exists())

    def test_invalid_values_fall_back_without_discarding_valid_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory))
            store.path.write_text(
                json.dumps({"max_file_size_mb": -1, "detect_personal_info": False}),
                encoding="utf-8",
            )

            config = store.load()

            self.assertEqual(config.max_file_size_mb, 5)
            self.assertFalse(config.detect_personal_info)

    def test_save_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory))
            store.save(AppConfig(max_file_size_mb=8))

            self.assertEqual(store.load().max_file_size_mb, 8)

    def test_entropy_settings_are_validated(self) -> None:
        config = AppConfig.from_dict({"min_entropy_length": 20, "entropy_threshold": 4.2})
        invalid = AppConfig.from_dict({"min_entropy_length": 2, "entropy_threshold": 9})

        self.assertEqual(config.min_entropy_length, 20)
        self.assertEqual(config.entropy_threshold, 4.2)
        self.assertEqual(invalid.min_entropy_length, 16)
        self.assertEqual(invalid.entropy_threshold, 3.8)


if __name__ == "__main__":
    unittest.main()
