import requests
import urllib.parse
import time
from utils.logger import Logger
from utils.alert import send_discord_alert
from datetime import datetime, timezone, timedelta

class Scanner:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.headers = {
            'User-Agent': 'DeepVulnScan-XSSQLi/1.0 (+https://github.com/yourrepo)'
        }
        self.delay = 1  # seconds between requests
        self.xss_payloads = self.load_payloads('payloads/xss_payloads.txt')
        self.sqli_payloads = self.load_payloads('payloads/sqli_payloads.txt')

    def load_payloads(self, filepath):
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.log(f"Payload file not found: {filepath}")
            return []

    def scan(self, url):
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            self.logger.log(f"No query parameters to test in URL: {url}")
            return

        base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        for param in params:
            original_value = params[param][0]
            # Test XSS
            for payload in self.xss_payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = base_url + "?" + urllib.parse.urlencode(test_params, doseq=True)
                resp = requests.get(test_url, headers=self.headers, timeout=10)
                time.sleep(self.delay)
                if payload in resp.text:
                    self.logger.log_vuln(url, "XSS", param, payload)
                    send_discord_alert(url, "XSS", param, payload)
                    break  # stop testing other XSS payloads on this param

            # Test SQLi
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = base_url + "?" + urllib.parse.urlencode(test_params, doseq=True)
                resp = requests.get(test_url, headers=self.headers, timeout=10)
                time.sleep(self.delay)
                if self.detect_sqli(resp.text):
                    self.logger.log_vuln(url, "SQLi", param, payload)
                    send_discord_alert(url, "SQLi", param, payload)
                    break  # stop testing other SQLi payloads on this param

    def detect_sqli(self, response_text):
        errors = [
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "mysql_fetch_array()",
            "syntax error",
            "sql syntax error",
            "mysql_num_rows()",
            "oracle error",
            "odbc sql server driver"
        ]
        lower_resp = response_text.lower()
        return any(err in lower_resp for err in errors)
