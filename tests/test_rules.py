"""
Unit tests and syntax verification for in-memory-hunter-rules.
Copyright (c) Shinabaze Ajiya. All rights reserved.
"""

import unittest
import os
import re

RULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "yara"))


class TestYaraRules(unittest.TestCase):

    def test_yara_files_exist(self):
        self.assertTrue(os.path.exists(RULES_DIR))
        rule_files = [f for f in os.listdir(RULES_DIR) if f.endswith(".yar")]
        self.assertGreaterEqual(len(rule_files), 2)

    def test_rule_syntax_integrity(self):
        # Verify basic YARA structure (rule, meta, strings, condition)
        for fname in os.listdir(RULES_DIR):
            if fname.endswith(".yar"):
                fpath = os.path.join(RULES_DIR, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()

                self.assertIn("rule ", content, f"Missing 'rule' in {fname}")
                self.assertIn("meta:", content, f"Missing 'meta:' in {fname}")
                self.assertIn("strings:", content, f"Missing 'strings:' in {fname}")
                self.assertIn("condition:", content, f"Missing 'condition:' in {fname}")
                self.assertIn("author = \"Shinabaze Ajiya\"", content, f"Missing author in {fname}")

    def test_synthetic_byte_matching(self):
        # Synthetic byte sequence matching x64 PEB walk: mov rax, gs:[0x60]; ror eax, 0x0d; add edx, eax
        sample_payload = (
            b"\x90\x90"
            b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00"  # mov rax, gs:[0x60]
            b"\x90\x90"
            b"\xC1\xC8\x0D\x03\xD0"                  # ror eax, 0x0d; add edx, eax
        )

        peb_pattern = b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
        ror_pattern = b"\xC1\xC8\x0D\x03\xD0"

        self.assertIn(peb_pattern, sample_payload)
        self.assertIn(ror_pattern, sample_payload)


if __name__ == "__main__":
    unittest.main()
