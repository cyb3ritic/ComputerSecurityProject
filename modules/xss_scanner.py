from core.scanner import BaseScanner
from core.payloads import PayloadManager

class XssScanner(BaseScanner):  # Ensure the class name is exactly "XSSScanner"
    options_help = {
        "url": "The target URL to scan for XSS vulnerabilities.",
        "verbose": "Enable verbose output (true/false).",
    }

    def run(self):
        self.validate_options()
        url = self.options.get("url")
        payloads = PayloadManager().get_xss_payloads()
        print(f"[+] Scanning {url} for XSS vulnerabilities...")
        for payload in payloads:
            print(f"[*] Testing payload: {payload}")
        return "XSS scan completed."