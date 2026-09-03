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
        self.assertGreater(by_rule["china_id_card"].score, by_rule["email_address"].score)
        self.assertNotEqual(by_rule["private_key_header"].severity, "critical")
        self.assertTrue(any("缺少完整 PEM" in factor.detail for factor in by_rule["private_key_header"].risk_factors))
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

    def test_complete_private_key_pem_is_critical_without_storing_body(self) -> None:
        body = "MIIE" + "A" * 76
        finding = self.scan_files({
            "src/server.conf": "\n".join([
                "-----BEGIN PRIVATE KEY-----",
                body,
                "-----END PRIVATE KEY-----",
            ])
        }).findings[0]

        self.assertEqual(finding.severity, "critical")
        self.assertTrue(any(factor.key == "complete_pem" for factor in finding.risk_factors))
        self.assertNotIn(body, finding.masked_value)
        self.assertNotIn(body, finding.context)

    def test_private_key_header_alone_is_not_critical(self) -> None:
        finding = self.scan_files({"src/constants.py": "-----BEGIN PRIVATE KEY-----"}).findings[0]

        self.assertNotEqual(finding.severity, "critical")
        self.assertLess(finding.score, 75)

    def test_masking_private_key_header_is_explained_as_detector_feature(self) -> None:
        finding = self.scan_files({
            "codeshield/masking.py": 'HEADER = "-----BEGIN PRIVATE KEY-----"',
        }).findings[0]

        self.assertEqual(finding.severity, "low")
        self.assertTrue(any(factor.key == "detector_rule_feature" for factor in finding.risk_factors))

    def test_test_and_demo_credentials_remain_detected_with_source_penalty(self) -> None:
        value = "A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL"
        result = self.scan_files({
            "tests/test_auth.py": f'api_key = "{value}"',
            "demo_project/auth.py": f'api_key = "{value}"',
        })

        self.assertEqual(len(result.findings), 2)
        for finding in result.findings:
            self.assertTrue(any(factor.key == "test_path" for factor in finding.risk_factors))

    def test_third_party_and_sbom_email_are_low_and_explained(self) -> None:
        result = self.scan_files({
            "site-packages/package/metadata.py": 'author = "maintainer@python.org"',
            "sboms/components.json": '"author": "person@gmail.com"',
        })

        self.assertEqual(len(result.findings), 2)
        for finding in result.findings:
            self.assertEqual(finding.severity, "low")
            self.assertTrue(any(factor.key == "third_party_source" for factor in finding.risk_factors))
            self.assertTrue(any(factor.key == "public_contact" for factor in finding.risk_factors))

    def test_business_api_key_stays_high_risk(self) -> None:
        value = "A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL"
        finding = self.scan_files({"src/config.py": f'api_key = "{value}"'}).findings[0]

        self.assertIn(finding.severity, {"high", "critical"})
        self.assertFalse(any(factor.points < 0 for factor in finding.risk_factors))

    def test_codeshield_business_secret_is_not_treated_as_rule_feature(self) -> None:
        value = "A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL"
        finding = self.scan_files({"codeshield/config.py": f'api_key = "{value}"'}).findings[0]

        self.assertIn(finding.severity, {"high", "critical"})
        self.assertFalse(any(factor.key == "detector_rule_feature" for factor in finding.risk_factors))


if __name__ == "__main__":
    unittest.main()
