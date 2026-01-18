from app import check_url_safety
import unittest

class TestURLSafety(unittest.TestCase):
    def test_missing_scheme(self):
        result = check_url_safety("google.com")
        self.assertIn("Not using HTTPS (data not encrypted)", result['warnings']) 
        # Note: app.py prepends http://, so it should flag "Not using HTTPS" because it is http
        
    def test_ip_address(self):
        result = check_url_safety("http://1.1.1.1")
        self.assertIn("IP address used instead of domain", result['warnings'])

    def test_invalid_ip(self):
        result = check_url_safety("http://999.999.999.999")
        self.assertNotIn("IP address used instead of domain", result['warnings'])

    def test_standard_url(self):
        result = check_url_safety("https://example.com")
        self.assertNotIn("Not using HTTPS (data not encrypted)", result['warnings'])

if __name__ == '__main__':
    unittest.main()
