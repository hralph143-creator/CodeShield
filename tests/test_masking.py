import unittest

from codeshield.masking import mask_value


class MaskingTests(unittest.TestCase):
    def test_personal_information_masking(self) -> None:
        self.assertEqual(mask_value("13812345678", "Phone"), "138****5678")
        self.assertEqual(mask_value("990000199001011239", "ID Card"), "990***********1239")
        self.assertEqual(mask_value("person@example.invalid", "Email"), "p***@example.invalid")

    def test_credentials_never_return_original_value(self) -> None:
        values = [
            ("DemoPassword", "Password"),
            ("demoToken00000000", "Token"),
            ("postgresql://user:pass@host/db", "Database Credential"),
            ("-----BEGIN RSA PRIVATE KEY-----", "Private Key"),
        ]
        for value, risk_type in values:
            with self.subTest(risk_type=risk_type):
                self.assertNotEqual(mask_value(value, risk_type), value)


if __name__ == "__main__":
    unittest.main()
