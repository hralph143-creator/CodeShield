import unittest
from pathlib import Path

from codeshield.context import analyze_context, is_placeholder_value, normalize_identifier


def analyze(line: str, value: str, path: str = "src/app.py"):
    start = line.index(value)
    return analyze_context([line], 0, (start, start + len(value)), value, Path(path))


class ContextTests(unittest.TestCase):
    def test_identifier_normalization(self) -> None:
        self.assertEqual(normalize_identifier("clientSecret"), ("client", "secret"))
        self.assertEqual(normalize_identifier("CLIENT_SECRET"), ("client", "secret"))
        self.assertEqual(normalize_identifier("client-secret"), ("client", "secret"))

    def test_hardcoded_sensitive_assignment(self) -> None:
        evidence = analyze('const apiKey = "A9fK2mQ7xT4vN8pR";', "A9fK2mQ7xT4vN8pR")
        self.assertEqual(evidence.variable_name, "apiKey")
        self.assertTrue(evidence.is_sensitive_variable)
        self.assertTrue(evidence.is_hardcoded)
        self.assertFalse(evidence.is_safe_source)

    def test_environment_and_dynamic_sources(self) -> None:
        cases = [
            ('password = os.getenv("DB_PASSWORD")', "DB_PASSWORD"),
            ('api_key = os.environ.get("API_KEY")', "API_KEY"),
            ('const token = process.env.ACCESS_TOKEN', "ACCESS_TOKEN"),
            ('String password = System.getenv("DB_PASSWORD")', "DB_PASSWORD"),
            ('let token = std::env::var("TOKEN")', "TOKEN"),
            ('password <- Sys.getenv("DB_PASSWORD")', "DB_PASSWORD"),
            ('token = load_secret()', "load_secret"),
            ('password = config.get("DB_PASSWORD")', "DB_PASSWORD"),
        ]
        for line, value in cases:
            with self.subTest(line=line):
                evidence = analyze(line, value)
                self.assertTrue(evidence.is_safe_source)
                self.assertFalse(evidence.is_hardcoded)

        reference = analyze("token = runtime_token", "runtime_token")
        self.assertFalse(reference.is_hardcoded)

    def test_comment_and_path_evidence_only_marks_penalties(self) -> None:
        for line in (
            '# password = "DemoPassword"',
            '// token = "DemoToken0000"',
            '<!-- api_key = "DemoKey0000" -->',
        ):
            value = next(part for part in ("DemoPassword", "DemoToken0000", "DemoKey0000") if part in line)
            self.assertTrue(analyze(line, value).is_comment)

        self.assertTrue(analyze('token = "DemoToken0000"', "DemoToken0000", "tests/demo.py").is_test_path)
        self.assertFalse(analyze('token = "DemoToken0000"', "DemoToken0000", "src/app.py").is_test_path)

    def test_placeholder_values(self) -> None:
        for value in ("demo", "test", "example", "your_api_key", "changeme", "xxxx"):
            self.assertTrue(is_placeholder_value(value))
        self.assertFalse(is_placeholder_value("A9fK2mQ7xT4vN8pR3sW6yB1c"))


if __name__ == "__main__":
    unittest.main()
