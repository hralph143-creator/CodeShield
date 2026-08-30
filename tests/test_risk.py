import tempfile
import unittest
from pathlib import Path

from codeshield.config import AppConfig
from codeshield.risk import severity_for_score
from codeshield.scanner import ProjectScanner


class RiskTests(unittest.TestCase):
    def scan_files(self, files: dict[str, str]):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for relative_path, content in files.items():
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        result = ProjectScanner(AppConfig()).scan(root)
        temporary.cleanup()
        return result

    def test_relative_risk_levels(self) -> None:
        result = self.scan_files({
            "src/app.py": '\n'.join([
                'api_key = "A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL"',
                'app_key = "demo_api_key_0000"',
                'password = "SimplePassword"',
                'email = "person@example.invalid"',
                'id_number = "990000199001011239"',
                '-----BEGIN PRIVATE KEY-----',
            ])
        })
        api_findings = [item for item in result.findings if item.rule_id == "api_key_assignment"]
        by_rule = {finding.rule_id: finding for finding in result.findings if finding.rule_id != "api_key_assignment"}

        self.assertGreater(api_findings[0].score, by_rule["password_assignment"].score)
        self.assertGreater(api_findings[0].score, api_findings[1].score)
        self.assertGreater(by_rule["private_key_header"].score, by_rule["password_assignment"].score)
        self.assertGreater(by_rule["china_id_card"].score, by_rule["email_address"].score)
        self.assertEqual(by_rule["private_key_header"].severity, "critical")
        self.assertEqual(by_rule["email_address"].severity, "low")
        self.assertTrue(all(0 <= item.score <= 100 for item in result.findings))

    def test_severity_boundaries(self) -> None:
        cases = {
            0: "low", 29: "low", 30: "medium", 49: "medium",
            50: "high", 74: "high", 75: "critical", 100: "critical",
        }
        for score, expected in cases.items():
            self.assertEqual(severity_for_score(score), expected)

    def test_path_comment_and_placeholder_reduce_score_without_filtering(self) -> None:
        value = "A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL"
        result = self.scan_files({
            "src/app.py": f'api_key = "{value}"',
            "tests/app.py": f'api_key = "{value}"',
            "src/comment.py": f'# api_key = "{value}"',
            "src/placeholder.py": 'api_key = "demo_api_key_0000"',
        })
        findings = {Path(item.relative_path).as_posix(): item for item in result.findings}

        self.assertGreater(findings["src/app.py"].score, findings["tests/app.py"].score)
        self.assertGreater(findings["src/app.py"].score, findings["src/comment.py"].score)
        self.assertGreater(findings["src/app.py"].score, findings["src/placeholder.py"].score)
        self.assertEqual(len(findings), 4)

    def test_database_sources_and_unrelated_entropy(self) -> None:
        result = self.scan_files({
            "db.env": '\n'.join([
                'PLAIN="mysql://user:PlainPassword123@localhost/test"',
                'DYNAMIC="mysql://user:${DB_PASSWORD}@localhost/test"',
                'SAFE="mysql://localhost/test"',
            ]),
            "hash.py": 'build_id = "A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL"',
        })
        db_findings = [item for item in result.findings if item.risk_type == "Database Credential"]

        self.assertEqual(len(db_findings), 2)
        self.assertGreater(db_findings[0].score, db_findings[1].score)
        self.assertFalse(any(item.relative_path == "hash.py" for item in result.findings))

    def test_finding_never_keeps_raw_value(self) -> None:
        raw = "A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL"
        finding = self.scan_files({"app.py": f'api_key = "{raw}"'}).findings[0]

        self.assertNotEqual(finding.masked_value, raw)
        self.assertNotIn(raw, finding.context)
        self.assertNotIn(raw, finding.reason)
        self.assertTrue(finding.risk_factors)


if __name__ == "__main__":
    unittest.main()
