import tempfile
import unittest
from pathlib import Path

from analyzer import analyze_email, extract_urls, normalize_url


class AnalyzerTests(unittest.TestCase):
    def test_extract_urls(self):
        urls = extract_urls("Visit https://example.com/a. and www.example.org")
        self.assertIn("https://example.com/a", urls)
        self.assertIn("www.example.org", urls)

    def test_normalize_url(self):
        self.assertEqual(normalize_url("www.example.com"), "http://www.example.com/")
        self.assertEqual(normalize_url("javascript:alert(1)"), "")

    def test_sample_email_is_flagged(self):
        sample = b"""From: GitHub Security <noreply@github.com>\nReply-To: <help@protonmail.com>\nSubject: Verify your account immediately\nContent-Type: text/plain; charset=utf-8\n\nVerify your identity within 24 hours: http://github-account-recovery-secure.com/login\n"""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.eml"
            path.write_bytes(sample)
            result = analyze_email(path, check_reputation=False)
        self.assertGreaterEqual(result["risk"]["score"], 30)
        self.assertIn(result["risk"]["classification"], {"Suspicious", "Likely Phishing"})
        self.assertTrue(result["content_analysis"]["url_analysis"])


if __name__ == "__main__":
    unittest.main()
