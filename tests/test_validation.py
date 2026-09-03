import unittest

from codeshield.validation import (
    database_credential_kind,
    validate_china_id,
    validate_jwt_structure,
    validate_private_key_structure,
)


VALID_JWT = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiJkZW1vIn0."
    "signature0000"
)


class ValidationTests(unittest.TestCase):
    def test_china_id_checksum_and_date(self) -> None:
        self.assertTrue(validate_china_id("990000199001011239"))
        self.assertTrue(validate_china_id("99000019900101005X"))
        self.assertTrue(validate_china_id("99000019900101005x"))
        self.assertFalse(validate_china_id("990000199001011238"))
        self.assertFalse(validate_china_id("990000199013011239"))
        self.assertFalse(validate_china_id("99000019900101123"))
        self.assertFalse(validate_china_id("9900001990010112390"))
        self.assertFalse(validate_china_id("123456789012345678"))

    def test_jwt_structure(self) -> None:
        self.assertTrue(validate_jwt_structure(VALID_JWT))
        self.assertFalse(validate_jwt_structure("abc.def"))
        self.assertFalse(validate_jwt_structure("abc.def.ghi!"))
        self.assertFalse(validate_jwt_structure("abc.def.ghi"))
        self.assertFalse(validate_jwt_structure("one.two.three.four"))

    def test_database_credential_kinds(self) -> None:
        self.assertEqual(database_credential_kind("mysql://localhost/test"), "none")
        self.assertEqual(database_credential_kind("mysql://user:pass@localhost/test"), "plaintext")
        self.assertEqual(
            database_credential_kind("mysql://user:${DB_PASSWORD}@localhost/test"),
            "dynamic",
        )

    def test_private_key_requires_body_and_matching_end_marker(self) -> None:
        header = "-----BEGIN PRIVATE KEY-----"
        complete = [header, "MIIE" + "A" * 76, "-----END PRIVATE KEY-----"]
        wrong_end = [header, "MIIE" + "A" * 76, "-----END RSA PRIVATE KEY-----"]

        self.assertTrue(validate_private_key_structure(complete, 0, header))
        self.assertFalse(validate_private_key_structure([header], 0, header))
        self.assertFalse(validate_private_key_structure(wrong_end, 0, header))


if __name__ == "__main__":
    unittest.main()
