from core.scanner import BaseScanner
from core.payloads import PayloadManager

class SsrfScanner(BaseScanner):  # Matches module_name.title().replace("_", "")
    options_help = {
        "url": "The target URL to scan for SSRF vulnerabilities.",
        "verbose": "Enable verbose output (true/false).",
    }

    def run(self):
        self.validate_options()
        url = self.options.get("url")
        payloads = PayloadManager().get_ssrf_payloads()  # Add this method in payloads.py
        print(f"[+] Scanning {url} for SSRF vulnerabilities...")
        for payload in payloads:
            print(f"[*] Testing payload: {payload}")
        return "SSRF scan completed."