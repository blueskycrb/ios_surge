import tempfile
import unittest
from pathlib import Path

from scripts.merge_rules import (
    CoverageIndex,
    apply_category_precedence,
    dedupe_rules,
    normalize_rule,
    parse_rules,
    write_rule_file,
)


class NormalizeRuleTests(unittest.TestCase):
    def test_normalizes_domain_and_cidr_rules(self):
        self.assertEqual(normalize_rule("DOMAIN-SUFFIX, OpenAI.COM. "), "DOMAIN-SUFFIX,openai.com")
        self.assertEqual(normalize_rule("IP-CIDR, 1.1.1.1, no-resolve"), "IP-CIDR,1.1.1.1/32,no-resolve")

    def test_rejects_invalid_rules(self):
        self.assertEqual(normalize_rule("IP-ASN,not-a-number"), "")
        self.assertEqual(normalize_rule("IP-CIDR,not-an-ip"), "")
        self.assertEqual(normalize_rule("UNKNOWN,example.com"), "")

    def test_splits_multiple_rules_on_one_line(self):
        rules = parse_rules("DOMAIN, a.example DOMAIN-SUFFIX, example.org")
        self.assertEqual(rules, {"DOMAIN,a.example", "DOMAIN-SUFFIX,example.org"})


class DedupeTests(unittest.TestCase):
    def test_prefers_no_resolve(self):
        rules = dedupe_rules({"IP-CIDR,1.1.1.1/32", "IP-CIDR,1.1.1.1/32,no-resolve"})
        self.assertEqual(rules, {"IP-CIDR,1.1.1.1/32,no-resolve"})

    def test_domain_suffix_and_keyword_cover_specific_domains(self):
        index = CoverageIndex({"DOMAIN-SUFFIX,openai.com", "DOMAIN-KEYWORD,copilot"})
        self.assertTrue(index.covers("DOMAIN,api.openai.com"))
        self.assertTrue(index.covers("DOMAIN-SUFFIX,chat.openai.com"))
        self.assertTrue(index.covers("DOMAIN,github-copilot.example"))
        self.assertFalse(index.covers("DOMAIN,example.com"))

    def test_cidr_covers_subnet(self):
        index = CoverageIndex({"IP-CIDR,1.1.1.0/24,no-resolve"})
        self.assertTrue(index.covers("IP-CIDR,1.1.1.1/32"))
        self.assertFalse(index.covers("IP-CIDR,1.1.2.0/24"))

    def test_applies_ai_proxy_china_precedence(self):
        ai, proxy, china, removed = apply_category_precedence(
            {"DOMAIN-SUFFIX,openai.com"},
            {"DOMAIN,api.openai.com", "DOMAIN-SUFFIX,google.com"},
            {"DOMAIN-SUFFIX,google.com", "DOMAIN-SUFFIX,baidu.com"},
        )
        self.assertEqual(ai, {"DOMAIN-SUFFIX,openai.com"})
        self.assertEqual(proxy, {"DOMAIN-SUFFIX,google.com"})
        self.assertEqual(china, {"DOMAIN-SUFFIX,baidu.com"})
        self.assertEqual(len(removed["Proxy"]), 1)
        self.assertEqual(len(removed["China"]), 1)


class WriteTests(unittest.TestCase):
    def test_does_not_rewrite_unchanged_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ai.list"
            rules = {"DOMAIN-SUFFIX,openai.com"}
            self.assertTrue(write_rule_file(path, "AI", rules))
            first_content = path.read_text(encoding="utf-8")
            self.assertFalse(write_rule_file(path, "AI", rules))
            self.assertEqual(path.read_text(encoding="utf-8"), first_content)


if __name__ == "__main__":
    unittest.main()
