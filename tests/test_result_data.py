import unittest

from codeshield.models import Finding, RiskFactor
from codeshield.ui.result_data import detail_data, filter_findings


def finding(
    rule_id: str,
    risk_type: str,
    severity: str,
    score: int,
    path: str,
    language: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=f"{risk_type} Rule",
        risk_type=risk_type,
        severity=severity,
        score=score,
        file_path=f"C:/project/{path}",
        relative_path=path,
        line_number=4,
        column=10,
        language=language,
        masked_value="demo********0000",
        reason="规则命中",
        suggestion="改用环境变量",
        entropy=4.2,
        risk_factors=(RiskFactor("rule", 40, "命中规则"),),
        context="4: api_key = demo********0000",
    )


class ResultDataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.findings = [
            finding("api", "API Key", "critical", 82, "src/config.py", "python"),
            finding("token", "Token", "high", 66, "web/auth.ts", "typescript"),
            finding("mail", "Email", "low", 20, "src/contact.py", "python"),
        ]

    def test_individual_and_combined_filters(self) -> None:
        self.assertEqual(len(filter_findings(self.findings, severity="critical")), 1)
        self.assertEqual(len(filter_findings(self.findings, risk_type="Token")), 1)
        self.assertEqual(len(filter_findings(self.findings, language="python")), 2)
        self.assertEqual(len(filter_findings(self.findings, keyword="config")), 1)
        combined = filter_findings(
            self.findings,
            keyword="src",
            severity="critical",
            risk_type="API Key",
            language="python",
        )
        self.assertEqual([item.rule_id for item in combined], ["api"])
        self.assertEqual(len(filter_findings(self.findings)), 3)

    def test_default_sorting(self) -> None:
        ordered = filter_findings(list(reversed(self.findings)))
        self.assertEqual([item.severity for item in ordered], ["critical", "high", "low"])

    def test_detail_uses_only_safe_finding_fields(self) -> None:
        item = self.findings[0]
        data = detail_data(item)

        self.assertEqual(data["score"], "82 / 100")
        self.assertEqual(data["risk_type"], "API Key")
        self.assertEqual(data["factors"], ["+40  命中规则"])
        self.assertNotIn("full-secret", " ".join(str(value) for value in data.values()))


if __name__ == "__main__":
    unittest.main()
