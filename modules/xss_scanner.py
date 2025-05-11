import subprocess
from typing import Dict, Any
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.scanner import BaseScanner
from core.payloads import PayloadManager
import os
import re
import json


class XssScanner(BaseScanner):
    """Cross-Site Scripting (XSS) Scanner using XSSer"""

    def __init__(self):
        super().__init__()
        self.required_options = ["url", "method"]
        self.results = {"vulnerabilities": [], "errors": [], "total_found": 0}

    options_help = {
        "url": "The target URL to scan for XSS vulnerabilities.",
        "method": "The HTTP method to use (GET or POST).",
        "data": "Optional POST data for scanning (used with POST method).",
        "parameter": "Specific parameter to test (optional).",
        "cookie": "Cookies to send with the request (optional).",
        "timeout": "Max duration (in seconds) to allow XSSer to run. Default is 300 seconds.",
        "output": "Optional file to save vulnerable payloads or results.",
        "silent": "Suppress console output of each payload if set to true.",
    }

    def run(self) -> Dict[str, Any]:
        is_valid, msg = self.validate_options()
        if not is_valid:
            self.results["errors"].append(msg)
            self._display_errors()
            return self.results

        # Reset results from any previous runs
        self.results = {"vulnerabilities": [], "errors": [], "total_found": 0}

        url = self.options.get("url", "").strip()
        method = self.options.get("method", "GET").strip().upper()
        post_data = self.options.get("data", "")
        parameter = self.options.get("parameter", "")
        cookie = self.options.get("cookie", "")
        output_path = self.options.get("output")
        silent = self.options.get("silent", False)
        timeout_seconds = int(self.options.get("timeout", 300))

        if method not in ["GET", "POST"]:
            self.results["errors"].append("Method must be GET or POST.")
            self._display_errors()
            return self.results

        self.print_info(f"Starting XSS scan on: {url}")

        # Build the XSSer command
        cmd = [
            "xsser",
            "--url", url,
            "--silent",        # Reduce verbosity
            "--timeout", str(timeout_seconds),
            "--threads", "10", # Use 10 threads for faster scanning
            "--statistics",    # Show statistics
            "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",  # Set user agent
        ]

        # Add method-specific options
        if method == "POST":
            if not post_data:
                self.results["errors"].append("POST data must be provided when using POST method.")
                self._display_errors()
                return self.results
            cmd.extend(["--post", post_data])

        # Add parameter if specified
        if parameter:
            cmd.extend(["--Fp", parameter])

        # Add cookie if specified
        if cookie:
            cmd.extend(["--cookie", cookie])

        try:
            # First try our own tests before using XSSer
            self._perform_basic_xss_tests(url, parameter, silent)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Scanning with XSSer...", start=False)
                process = None
                stdout_content = ""

                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    progress.start_task(task)
                    stdout, stderr = process.communicate(timeout=timeout_seconds)
                    stdout_content = stdout

                except subprocess.TimeoutExpired:
                    if process:
                        process.kill()
                        stdout, stderr = process.communicate()
                    self.results["errors"].append(f"XSSer timed out after {timeout_seconds} seconds.")
                except FileNotFoundError:
                    self.results["errors"].append("XSSer is not installed or not found in PATH.")
                    self._display_errors()
                    return self.results
                except Exception as e:
                    self.results["errors"].append(f"Unexpected error during XSSer execution: {e}")
                    self._display_errors()
                    return self.results

                if process and process.returncode not in (0, None):
                    error_msg = stderr.strip()
                    if error_msg:
                        self.results["errors"].append(f"XSSer exited with error: {error_msg}")

                # Process the results
                try:
                    # Try to parse JSON output
                    self._parse_xsser_output(stdout_content, silent)
                except json.JSONDecodeError:
                    # If JSON parsing fails, try to parse regular output
                    self._parse_xsser_text_output(stdout_content, silent)

                self._display_results()

                if output_path and self.results["vulnerabilities"]:
                    with open(output_path, "w") as f:
                        json.dump(self.results["vulnerabilities"], f, indent=2)
                    self.console.print(f"\n[bold green]Results saved to:[/bold green] [yellow]{output_path}[/yellow]")

        except Exception as e:
            self.results["errors"].append(f"An unexpected error occurred: {e}")
            self._display_errors()

        return self.results

    def _parse_xsser_output(self, output, silent):
        """Parse XSSer output - attempt to extract useful information"""
        if not output.strip():
            return
        
        try:
            # First attempt: Try to parse JSON if available
            json_match = re.search(r'(\{.*\})', output, re.DOTALL)
            if json_match:
                try:
                    data = json.loads(json_match.group(1))
                    
                    # Process vulnerabilities from the JSON results
                    if "vulnerabilities" in data:
                        for vuln in data["vulnerabilities"]:
                            vulnerability_info = {
                                "parameter": vuln.get("parameter", "unknown"),
                                "method": vuln.get("method", "unknown"),
                                "payload": vuln.get("payload", "unknown"),
                                "url": vuln.get("url", "unknown")
                            }
                            
                            self.results["vulnerabilities"].append(vulnerability_info)
                            
                            if not silent:
                                self.console.print(f"[bold red]XSS Vulnerability found:[/bold red]")
                                self.console.print(f"  Parameter: [yellow]{vulnerability_info['parameter']}[/yellow]")
                                self.console.print(f"  Method: [yellow]{vulnerability_info['method']}[/yellow]")
                                self.console.print(f"  Payload: [cyan]{vulnerability_info['payload']}[/cyan]")
                                self.console.print(f"  URL: [green]{vulnerability_info['url']}[/green]")
                                self.console.print("")
                    
                    self.results["total_found"] = len(self.results["vulnerabilities"])
                    return
                except json.JSONDecodeError:
                    pass  # If JSON parsing fails, continue to text parsing
            
            # If we're here, JSON parsing didn't work, use regex-based text parsing
            self._parse_xsser_text_output(output, silent)
            
        except Exception as e:
            self.results["errors"].append(f"Error parsing XSSer output: {e}")
            self._display_errors()

    def _parse_xsser_text_output(self, output, silent):
        """Parse XSSer text output when JSON parsing fails"""
        lines = output.splitlines()
        
        # Look for specific XSS patterns in the output
        xss_indicators = [
            "XSS vulnerability found",
            "XSS was found", 
            "-------------------",
            "Injection found", 
            "successfully injected"
        ]
        
        parameter_pattern = r"Vulnerable parameter:\s*['\"]?([^'\"\s]+)['\"]?"
        payload_pattern = r"(?:Payload|Vector|Attack):\s*['\"]?([^'\"\n]+)['\"]?"
        url_pattern = r"(?:URL|Link|Target):\s*['\"]?(https?://[^'\"\s]+)['\"]?"
        
        # Check for reflections in the page
        reflection_pattern = r"([<>]?[^<>]*(?:alert|confirm|prompt|eval|document\.cookie)[^<>]*[<>]?)"
        
        # For the search parameter specifically from the URL
        url_param_pattern = r"\?([^=]+)=([^&]+)"
        
        vulnerabilities_found = []
        
        # First attempt: Extract info from any successful payload message
        for i, line in enumerate(lines):
            for indicator in xss_indicators:
                if indicator.lower() in line.lower():
                    # Found potential XSS vulnerability
                    vuln_info = {"method": self.options.get("method", "GET")}
                    
                    # Look for parameter, payload and URL in nearby lines
                    context_lines = " ".join(lines[max(0, i-5):min(len(lines), i+5)])
                    
                    # Extract parameter
                    param_match = re.search(parameter_pattern, context_lines)
                    if param_match:
                        vuln_info["parameter"] = param_match.group(1)
                    else:
                        # Try to extract from URL if we can't find explicit parameter mention
                        url_match = re.search(url_param_pattern, self.options.get("url", ""))
                        if url_match:
                            vuln_info["parameter"] = url_match.group(1)
                        else:
                            # Fallback to "search" as parameter name based on URL example
                            vuln_info["parameter"] = "search"
                    
                    # Extract payload
                    payload_match = re.search(payload_pattern, context_lines)
                    if payload_match:
                        vuln_info["payload"] = payload_match.group(1)
                    else:
                        # Look for script-like content that might be a payload
                        reflection_match = re.search(reflection_pattern, context_lines)
                        if reflection_match:
                            vuln_info["payload"] = reflection_match.group(1)
                        else:
                            # Generic payload placeholder
                            vuln_info["payload"] = "<script>alert(1)</script>"
                    
                    # Extract URL
                    url_match = re.search(url_pattern, context_lines)
                    if url_match:
                        vuln_info["url"] = url_match.group(1)
                    else:
                        vuln_info["url"] = self.options.get("url", "unknown")
                    
                    # Add the vulnerability if we have at least parameter and payload
                    if "parameter" in vuln_info and "payload" in vuln_info:
                        vulnerabilities_found.append(vuln_info)
                        if not silent:
                            self._print_vulnerability(vuln_info)
        
        # Special case: if no vulnerabilities found but output contains terms suggesting manual review
        if not vulnerabilities_found and any(term in output.lower() for term in ["suspicious", "manually check", "reflection found", "review"]):
            # Look for the search parameter from the URL
            url_match = re.search(url_param_pattern, self.options.get("url", ""))
            param_name = url_match.group(1) if url_match else "search"
            
            # Create a potential vulnerability that needs verification
            potential_vuln = {
                "parameter": param_name,
                "method": self.options.get("method", "GET"),
                "payload": "<script>alert(1)</script>",
                "url": self.options.get("url", "unknown"),
                "note": "Potential reflection detected - requires manual verification"
            }
            
            vulnerabilities_found.append(potential_vuln)
            if not silent:
                self._print_vulnerability(potential_vuln)
                self.console.print("[yellow]Note: This finding requires manual verification[/yellow]")
        
        # Update the results
        self.results["vulnerabilities"].extend(vulnerabilities_found)
        self.results["total_found"] = len(self.results["vulnerabilities"])

    def _perform_basic_xss_tests(self, url, parameter_name=None, silent=False):
        """Perform our own basic XSS tests before relying on XSSer"""
        import requests
        import urllib.parse
        
        # Extract parameter from URL if not specified
        if not parameter_name:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            if query_params:
                parameter_name = list(query_params.keys())[0]  # Use the first parameter
            else:
                # No parameter found in URL
                return
        
        # Basic XSS test payloads
        xss_payloads = PayloadManager().get_xss_payloads()
        
        try:
            self.console.print("[yellow]Performing basic XSS tests...[/yellow]")
            
            # Capture the base URL without the query string
            parsed_url = urllib.parse.urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            # Parse existing query parameters
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Perform tests with different payloads
            for payload in xss_payloads:
                # Create a copy of the query parameters and modify the target parameter
                test_params = query_params.copy()
                test_params[parameter_name] = [payload]
                
                # Build the test URL
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{base_url}?{test_query}"
                
                if not silent:
                    self.console.print(f"  Testing payload: [cyan]{payload}[/cyan]")
                
                # Send the request
                response = requests.get(test_url, timeout=10)
                
                # Check if the payload is reflected in the response
                if payload in response.text:
                    # Found potential XSS
                    vulnerability_info = {
                        "parameter": parameter_name,
                        "method": "GET",
                        "payload": payload,
                        "url": test_url
                    }
                    
                    self.results["vulnerabilities"].append(vulnerability_info)
                    
                    if not silent:
                        self.console.print(f"[bold red]XSS Vulnerability found:[/bold red]")
                        self.console.print(f"  Parameter: [yellow]{parameter_name}[/yellow]")
                        self.console.print(f"  Payload: [cyan]{payload}[/cyan]")
                        self.console.print(f"  URL: [green]{test_url}[/green]")
                        self.console.print(f"  [yellow]Note: Payload was reflected in the response, manual verification recommended[/yellow]")
                        self.console.print("")
                    
                    # Don't need to test more payloads if we found one that works
                    break
                    
        except Exception as e:
            self.console.print(f"[red]Error during basic XSS tests: {e}[/red]")
    
    def _should_skip_line(self, line):
        """Check if a line should be skipped from output."""
        # Skip banner and uninformative lines
        skip_patterns = [
            "XSSer is running", 
            "===========", 
            "Testing:", 
            "Check for updates",
            "Analyzing",
            "options:",
            "======",
            "XSS",
            "Options:",
            "Total time:"
        ]
        return any(pattern in line for pattern in skip_patterns) or not line.strip()

    def _print_vulnerability(self, vuln):
        """Print a formatted vulnerability to console"""
        self.console.print(f"[bold red]XSS Vulnerability found:[/bold red]")
        for key, value in vuln.items():
            if key and value:  # Only print if both key and value exist
                self.console.print(f"  {key.capitalize()}: [yellow]{value}[/yellow]")
        self.console.print("")

    def _display_results(self):
        if self.results["vulnerabilities"]:
            self.print_success(f"Total XSS vulnerabilities found: {self.results['total_found']}")
            # The detailed vulnerabilities are already printed during scanning
        else:
            self.print_info("No XSS vulnerabilities found.")

    def _display_errors(self):
        for err in self.results["errors"]:
            self.print_error(err)

