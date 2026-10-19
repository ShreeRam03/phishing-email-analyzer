import os
import unittest

from phish_analyzer import checks
from phish_analyzer.__main__ import build_report
from phish_analyzer.parser import parse_eml

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
PHISH = os.path.join(SAMPLES, "phish_paypal_lookalike.eml")
LEGIT = os.path.join(SAMPLES, "legit_newsletter.eml")


class ParserTests(unittest.TestCase):
    def test_extracts_headers_links_and_attachment(self):
        email = parse_eml(PHISH)
        self.assertEqual(email.from_addr, "security@paypa1-support.example")
        self.assertEqual(email.reply_to, "help-desk@freemail-box.example")
        self.assertEqual(len(email.attachments), 1)
        self.assertEqual(email.attachments[0].filename, "Invoice_Oct2026.pdf.exe")
        urls = [link.url for link in email.links]
        self.assertIn("http://198.51.100.23/login/paypal/verify.php", urls)
        self.assertIn("https://bit.ly/3xYzAbC", urls)


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.details = " | ".join(f.detail for f in checks.run_all(parse_eml(PHISH)))

    def test_flags_failed_authentication(self):
        self.assertIn("SPF = fail", self.details)
        self.assertIn("DMARC = fail", self.details)

    def test_flags_mismatched_link_text(self):
        self.assertIn("Link text shows www.paypal.com but goes to 198.51.100.23", self.details)

    def test_flags_double_extension(self):
        self.assertIn("Double extension: Invoice_Oct2026.pdf.exe", self.details)

    def test_flags_brand_in_display_name(self):
        self.assertIn("mentions 'paypal'", self.details)


class VerdictTests(unittest.TestCase):
    def test_phish_is_high_risk(self):
        report = build_report(PHISH, use_vt=False)
        self.assertGreaterEqual(report["score"], 60)
        self.assertTrue(report["verdict"].startswith("HIGH RISK"))

    def test_legit_is_low_risk(self):
        report = build_report(LEGIT, use_vt=False)
        self.assertLess(report["score"], 30, report["findings"])


if __name__ == "__main__":
    unittest.main()
