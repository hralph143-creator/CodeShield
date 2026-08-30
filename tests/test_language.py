import unittest
from pathlib import Path

from codeshield.language import detect_language, file_extension


class LanguageTests(unittest.TestCase):
    def test_supported_languages(self) -> None:
        cases = {
            "main.py": "python",
            "App.java": "java",
            "index.jsx": "javascript",
            "app.tsx": "typescript",
            "main.c": "c",
            "demo.hpp": "cpp",
            "analysis.R": "r",
            "main.rs": "rust",
            "application.yml": "config",
            ".env": "config",
        }
        for filename, expected in cases.items():
            with self.subTest(filename=filename):
                self.assertEqual(detect_language(Path(filename)), expected)

    def test_unknown_extension(self) -> None:
        self.assertIsNone(detect_language(Path("notes.txt")))
        self.assertEqual(file_extension(Path(".env")), ".env")


if __name__ == "__main__":
    unittest.main()
