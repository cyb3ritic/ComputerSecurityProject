import subprocess
from typing import Dict, Any
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.scanner import BaseScanner
import os
import re


class SqliScanner(BaseScanner):
    """SQL Injection Scanner using sqlmap"""

    def __init__(self):
        super().__init__()
        self.required_options = ["url", "method"]
        self.results = {"vulnerabilities": [], "errors": [], "total_found": 0}

    options_help = {
        "url": "The target URL to scan for SQLi vulnerabilities.",
        "method": "The HTTP method to use (GET or POST).",
        "data": "Optional POST data for scanning (used with POST method).",
        "timeout": "Max duration (in seconds) to allow sqlmap to run. Default is 300 seconds.",
        "output": "Optional file to save vulnerable payloads or results.",
        "silent": "Suppress console output of each payload if set to true.",
    }

    def run(self) -> Dict[str, Any]:
        is_valid, msg = self.validate_options()
        if not is_valid:
            self.results["errors"].append(msg)
            self._display_errors()
            return self.results

        url = self.options.get("url", "").strip()
        method = self.options.get("method", "GET").strip().upper()
        post_data = self.options.get("data", "")
        output_path = self.options.get("output")
        silent = self.options.get("silent", False)
        timeout_seconds = int(self.options.get("timeout", 300))

        if method not in ["GET", "POST"]:
            self.results["errors"].append("Method must be GET or POST.")
            self._display_errors()
            return self.results

        self.print_info(f"Starting SQLi scan on: {url}")

        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--technique=BEUSTQ",
            "--random-agent",
            "--level=4",
            "--silent",  # Keep the --silent flag
            "--risk=2",
            "--banner",  # Suppress sqlmap banner
            "--no-cast"  # For cleaner output
        ]

        if method == "POST":
            if not post_data:
                self.results["errors"].append("POST data must be provided when using POST method.")
                self._display_errors()
                return self.results
            cmd.extend(["--data", post_data])

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Scanning with sqlmap...", start=False)
                process = None
                stdout_lines = []

                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    task_started = False
                    while True:
                        line = process.stdout.readline()
                        if not line and process.poll() is not None:
                            break
                        
                        # Skip banner lines and other unwanted output
                        if self._should_skip_line(line):
                            continue
                            
                        stdout_lines.append(line.strip())
                        if not task_started:
                            progress.start_task(task)
                            task_started = True
                        
                        # Only display relevant information about vulnerabilities
                        if not silent and self._is_relevant_output(line):
                            self.console.print(line.strip())

                    stdout, stderr = process.communicate(timeout=timeout_seconds)

                except subprocess.TimeoutExpired:
                    if process:
                        process.kill()
                        stdout, stderr = process.communicate()
                    self.results["errors"].append(f"sqlmap timed out after {timeout_seconds} seconds.")
                except FileNotFoundError:
                    self.results["errors"].append("sqlmap is not installed or not found in PATH.")
                    self._display_errors()
                    return self.results
                except Exception as e:
                    self.results["errors"].append(f"Unexpected error during sqlmap execution: {e}")
                    self._display_errors()
                    return self.results

                if process and process.returncode not in (0, None):
                    error_msg = stderr.strip()
                    if error_msg:
                        self.results["errors"].append(f"sqlmap exited with error: {error_msg}")

                # Post-processing of stdout for vulnerability identification
                vulnerabilities_found_in_output = []
                parameter_regex = r"Parameter: (.+?) \((.*?)\)"
                payload_regex = r"Payload: (.+)"
                
                # To store current vulnerability being processed
                current_param = None
                current_type = None
                
                for line in stdout_lines:
                    param_match = re.search(parameter_regex, line)
                    if param_match:
                        current_param = param_match.group(1).strip()
                        current_type = param_match.group(2).strip()
                        continue
                        
                    payload_match = re.search(payload_regex, line)
                    if current_param and payload_match:
                        payload = payload_match.group(1).strip()
                        vulnerability_info = {
                            "parameter": current_param,
                            "type": current_type,
                            "payload": payload
                        }
                        
                        # Check if this is a new vulnerability
                        vuln_key = f"{current_param}:{current_type}"
                        if vuln_key not in vulnerabilities_found_in_output:
                            vulnerabilities_found_in_output.append(vuln_key)
                            self.results["vulnerabilities"].append(vulnerability_info)
                            if not silent:
                                self.console.print(f"[bold red]Vulnerability found:[/bold red]")
                                self.console.print(f"  Parameter: [yellow]{current_param}[/yellow]")
                                self.console.print(f"  Type: [yellow]{current_type}[/yellow]")
                                self.console.print(f"  Payload: [cyan]{payload}[/cyan]")
                                self.console.print("")

                self.results["total_found"] = len(self.results["vulnerabilities"])
                self._display_results()

                if output_path and self.results["vulnerabilities"]:
                    with open(output_path, "w") as f:
                        for vuln in self.results["vulnerabilities"]:
                            f.write(f"Parameter: {vuln.get('parameter')}\n")
                            f.write(f"Type: {vuln.get('type')}\n")
                            f.write(f"Payload: {vuln.get('payload')}\n\n")
                    self.console.print(f"\n[bold green]Results saved to:[/bold green] [yellow]{output_path}[/yellow]")

        except Exception as e:
            self.results["errors"].append(f"An unexpected error occurred: {e}")
            self._display_errors()

        return self.results

    def _should_skip_line(self, line):
        """Check if a line should be skipped from output."""
        # Skip sqlmap banner
        if any(x in line for x in ["legal disclaimer", "sqlmap.org", "__H__", "___", "developer"]):
            return True
        # Skip other noise
        if any(x in line for x in ["starting @", "ending @", "cookie", "resumed"]):
            return True
        # Skip empty lines
        if line.strip() == "":
            return True
        return False

    def _is_relevant_output(self, line):
        """Check if a line contains relevant vulnerability information to display."""
        important_patterns = [
            "Parameter:", "Type:", "Title:", "Payload:", 
            "vulnerability", "vulnerable", "injection point", 
            "back-end DBMS:", "available databases:"
        ]
        return any(pattern in line for pattern in important_patterns)

    def _display_results(self):
        if self.results["vulnerabilities"]:
            self.print_success(f"Total SQLi vulnerabilities found: {self.results['total_found']}")
            for i, vuln in enumerate(self.results["vulnerabilities"], 1):
                self.console.print(f"[bold green]{i}.[/bold green] Parameter: [yellow]{vuln.get('parameter')}[/yellow], "
                                  f"Type: [yellow]{vuln.get('type')}[/yellow]")
        else:
            self.print_info("No SQLi vulnerabilities found.")

    def _display_errors(self):
        for err in self.results["errors"]:
            self.print_error(err)