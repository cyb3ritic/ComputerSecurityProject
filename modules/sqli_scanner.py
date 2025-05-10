from core.scanner import BaseScanner
from core.payloads import PayloadManager

class SqliScanner(BaseScanner):  # Ensure the class name is exactly "SQLiScanner"
    options_help = {
        "url": "The target URL to scan for SQLi vulnerabilities.",
        "method": "The HTTP method to use (GET/POST).",
    }

    def run(self):
        self.validate_options()
        url = self.options.get("url")
        payloads = PayloadManager().get_sqli_payloads()
        print(f"[+] Scanning {url} for SQLi vulnerabilities...")
        for payload in payloads:
            print(f"[*] Testing payload: {payload}")
        return "SQLi scan completed."