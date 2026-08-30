import json
import tempfile
import unittest
from pathlib import Path

from codeshield.config import AppConfig
from codeshield.rules import RuleDetector, load_rules


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        loaded = load_rules()
        cls.rules = loaded.rules
        cls.detector = RuleDetector(cls.rules, AppConfig())

    def detect_types(self, text: str, language: str = "python") -> set[str]:
        findings = self.detector.detect(text, Path("demo.py"), Path("demo.py"), language)
        return {finding.risk_type for finding in findings}

    def test_builtin_rules_load(self) -> None:
        loaded = load_rules()
        self.assertEqual(len(loaded.rules), 11)
        self.assertEqual(loaded.errors, [])

    def test_invalid_regex_is_isolated(self) -> None:
        rules = [
            {
                "id": "broken",
                "name": "broken",
                "risk_type": "Token",
                "pattern": "(?P<value>[",
                "severity": "high",
                "score": 60,
                "languages": ["python"],
                "enabled": True,
                "description": "broken",
                "suggestion": "broken"
            },
            {
                "id": "valid",
                "name": "valid",
                "risk_type": "Token",
                "pattern": "token=(?P<value>[a-z]+)",
                "severity": "high",
                "score": 60,
                "languages": ["python"],
                "enabled": True,
                "description": "valid",
                "suggestion": "valid"
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            path.write_text(json.dumps(rules), encoding="utf-8")
            with self.assertLogs("codeshield.rules", level="WARNING"):
                loaded = load_rules(path)

        self.assertEqual([rule.id for rule in loaded.rules], ["valid"])
        self.assertEqual(len(loaded.errors), 1)

    def test_assignment_rules_and_environment_calls(self) -> None:
        text = '\n'.join([
            'password = "DemoPassword"',
            'api_key = "demoKey000000"',
            'client_secret: string = "demoSecret0000"',
            'token <- "demoToken0000"',
        ])
        self.assertTrue({"Password", "API Key", "Secret", "Token"} <= self.detect_types(text))
        safe = 'password = os.getenv("DB_PASSWORD")\napi_key = os.environ.get("API_KEY")'
        self.assertEqual(self.detect_types(safe), set())

    def test_quoted_json_key(self) -> None:
        self.assertIn("Token", self.detect_types('"token": "demoJsonToken0000"', "config"))

    def test_format_rules(self) -> None:
        text = '\n'.join([
            'jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJkZW1vIn0.signature0000"',
            '-----BEGIN OPENSSH PRIVATE KEY-----',
            'postgresql://demo:invalid@localhost/demo',
        ])
        self.assertTrue({"JWT", "Private Key", "Database Credential"} <= self.detect_types(text))

    def test_personal_info_switch(self) -> None:
        text = 'mail="person@example.invalid" phone="13800000000" id="990000199001011239"'
        self.assertTrue({"Email", "Phone", "ID Card"} <= self.detect_types(text))
        disabled = RuleDetector(self.rules, AppConfig(detect_personal_info=False))
        self.assertEqual(disabled.detect(text, Path("a.py"), Path("a.py"), "python"), [])

    def test_invalid_personal_data_and_phone_substring_are_rejected(self) -> None:
        text = 'bad_id="990000199013011239" order="9138000000001"'
        types = self.detect_types(text)
        self.assertNotIn("ID Card", types)
        self.assertNotIn("Phone", types)

    def test_invalid_jwt_is_rejected(self) -> None:
        self.assertNotIn("JWT", self.detect_types('token="eyJbroken.eyJbroken.signature0000"'))


if __name__ == "__main__":
    unittest.main()
