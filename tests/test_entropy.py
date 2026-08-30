import unittest

from codeshield.entropy import calculate_entropy


class EntropyTests(unittest.TestCase):
    def test_boundaries(self) -> None:
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy("a"), 0.0)
        self.assertEqual(calculate_entropy("aaaaaaaa"), 0.0)

    def test_character_variety_increases_entropy(self) -> None:
        repeated = calculate_entropy("1111111111111111")
        ordinary = calculate_entropy("hello security world")
        varied = calculate_entropy("A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL")

        self.assertGreater(ordinary, repeated)
        self.assertGreater(varied, ordinary)
        self.assertGreater(calculate_entropy("中文安全测试"), 0)


if __name__ == "__main__":
    unittest.main()
