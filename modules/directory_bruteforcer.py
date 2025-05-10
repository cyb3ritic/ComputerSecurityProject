import subprocess
import shutil
import re
from rich.console import Console
from rich.table import Table
from rich import box
from typing import Dict, List, Optional, Union, Any

class DirectoryBruteforcer:
    """
    A module for performing directory and file bruteforcing on a target URL using feroxbuster.
    Provides enhanced output and functionality.
    """
    def __init__(self, options: Optional[Dict[str, str]] = None):
        """
        Initializes the DirectoryBruteforcer with optional configuration.

        Args:
            options (Optional[Dict[str, str]]): A dictionary of options to configure the scan.
                Supported options include: 'url', 'wordlist', 'threads', 'timeout', 'depth',
                'status_codes', 'output'.
        """
        self.console = Console()
        self.options_help = {
            "url": "Target URL to scan (required).",
            "wordlist": "Path to wordlist for directory enumeration (default: /usr/share/seclists/Discovery/Web-Content/common.txt).",
            "threads": "Number of concurrent threads for scanning (default: 20).",
            "timeout": "Request timeout in seconds (default: 10).",
            "depth": "Recursion depth for directory scanning (default: 1).",
            "status_codes": "Comma-separated list of status codes to display (default: 200,204,301,302,307,401,403).",
            "output": "Optional path to save results in plain text format."
        }
        self.options = options or {}
        self.results: Dict[str, Union[List[str], int, List[str]]] = {
            "found_urls": [],  # Will store only URLs as strings
            "total_found": 0,
            "errors": [],
            "_full_entries": []  # Internal storage for display purposes
        }
        if not shutil.which("feroxbuster"):
            raise EnvironmentError("feroxbuster is not installed or not in PATH.")

    def run(self) -> Dict[str, Any]:
        """
        Executes the directory bruteforce scan using the configured options.

        Returns:
            Dict[str, Any]: A dictionary containing the results of the scan,
            including found URLs, the total number of found URLs, and any errors encountered.
        """
        url = self.options.get("url", "").rstrip("/")
        wordlist = self.options.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        threads = int(self.options.get("threads", 20))
        timeout = int(self.options.get("timeout", 10))
        depth = int(self.options.get("depth", 1))
        silent = self.options.get("silent", False)
        status_codes = self.options.get("status_codes", "200,204,301,302,307,401,403")
        output_path = self.options.get("output", None)

        if not url:
            self.results["errors"].append("Target URL is required.")
            self._display_errors()
            return self.results

        self.console.print(f"[bold blue]Starting directory bruteforce on:[/bold blue] [green]{url}[/green]")
        self.console.print(f"[bold blue]Using wordlist:[/bold blue] [yellow]{wordlist}[/yellow]")
        self.console.print(f"[bold blue]Threads:[/bold blue] [cyan]{threads}[/cyan]  [bold blue]Timeout:[/bold blue] [cyan]{timeout}s[/cyan]  [bold blue]Depth:[/bold blue] [cyan]{depth}[/cyan]")
        self.console.print(f"[bold blue]Status Codes:[/bold blue] [magenta]{status_codes}[/magenta]\n")

        cmd = [
            "feroxbuster",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "--timeout", str(timeout),
            "-d", str(depth),
            "--status-codes", status_codes,
            "-q"
        ]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Regex pattern to match feroxbuster output format
            # Format: STATUS_CODE  METHOD  LINES  WORDS  CHARS  URL [=> REDIRECT_URL]
            pattern = r'^(\d{3})\s+(\w+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(https?://[^\s]+)(?:\s+=>\s+(https?://[^\s]+))?'
            
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                line = line.strip()
                
                # Handle informational messages
                if "Auto-filtering" in line or line.startswith("Error:"):
                    if not silent:
                        self.console.print(f"[yellow]{line}[/yellow]")
                    continue
                
                # Try to match the standard output format
                match = re.match(pattern, line)
                if match:
                    status_code = match.group(1)
                    method = match.group(2)
                    lines = match.group(3)
                    words = match.group(4)
                    chars = match.group(5)
                    url = match.group(6)
                    redirect = match.group(7) if match.group(7) else None
                    
                    # Store just the URL in found_urls
                    self.results["found_urls"].append(url)
                    
                    # Store full entry details in _full_entries for display purposes
                    result_entry = {
                        "status_code": status_code,
                        "method": method,
                        "lines": lines,
                        "words": words,
                        "chars": chars,
                        "url": url,
                        "redirect": redirect
                    }
                    self.results["_full_entries"].append(result_entry)
                    
                    if not silent:
                        status_color = "green" if status_code.startswith("2") else ("yellow" if status_code.startswith("3") else "red")
                        redirect_info = f" => {redirect}" if redirect else ""
                        self.console.print(f"[{status_color}]{status_code}[/{status_color}]  [dim]{method}[/dim]  "
                                          f"[dim]{lines}l {words}w {chars}c[/dim]  {url}{redirect_info}")
                elif line:
                    # Handle any other output
                    if not silent:
                        self.console.print(f"[dim]{line}[/dim]")

            stdout, stderr = process.communicate()
            if process.returncode != 0:
                self.results["errors"].append(f"Feroxbuster error: {stderr.strip()}")
            elif not silent and stderr.strip():
                self.console.print(f"[yellow]Feroxbuster messages:[/yellow] [dim]{stderr.strip()}[/dim]")

            self.results["total_found"] = len(self.results["found_urls"])
            self._display_results()

            if output_path:
                with open(output_path, "w") as f:
                    for url in self.results["found_urls"]:
                        f.write(f"{url}\n")
                self.console.print(f"\n[bold green]Results saved to:[/bold green] [yellow]{output_path}[/yellow]")

        except FileNotFoundError:
            self.results["errors"].append("Error: The specified wordlist file was not found.")
            self._display_errors()
        except subprocess.CalledProcessError as e:
            self.results["errors"].append(f"Feroxbuster error: {e}")
            self._display_errors()
        except Exception as e:
            self.results["errors"].append(f"An unexpected error occurred: {e}")
            self._display_errors()
        del self.results["_full_entries"]
        return self.results

    def _display_results(self):
        """
        Displays the found URLs in a formatted table using the rich library.
        """
        if self.results["found_urls"]:
            self.console.print("\n[bold green]--- Found Directories/Files ---[/bold green]")
            table = Table(title="Discovered URLs", box=box.SIMPLE)
            table.add_column("[bold blue]Status[/bold blue]", style="bold")
            table.add_column("[bold blue]Method[/bold blue]")
            table.add_column("[bold blue]Lines[/bold blue]")
            table.add_column("[bold blue]Words[/bold blue]")
            table.add_column("[bold blue]Chars[/bold blue]")
            table.add_column("[bold blue]URL[/bold blue]")
            table.add_column("[bold blue]Redirect[/bold blue]")
            
            # Use _full_entries for display which contains all details
            for entry in sorted(self.results["_full_entries"], key=lambda x: x["url"]):
                status_color = "green" if entry["status_code"].startswith("2") else ("yellow" if entry["status_code"].startswith("3") else "red")
                table.add_row(
                    f"[{status_color}]{entry['status_code']}[/{status_color}]",
                    entry["method"],
                    entry["lines"],
                    entry["words"],
                    entry["chars"],
                    entry["url"],
                    entry["redirect"] if entry["redirect"] else ""
                )
            self.console.print(table)
            self.console.print(f"\n[bold green]Total Found:[/bold green] [cyan]{self.results['total_found']}[/cyan]")
        else:
            self.console.print("\n[bold yellow]No directories or files found matching the specified criteria.[/bold yellow]")

    def _display_errors(self):
        """
        Displays any errors encountered during the scan using the rich library.
        """
        if self.results["errors"]:
            self.console.print("\n[bold red]--- Errors ---[/bold red]")
            for error in self.results["errors"]:
                self.console.print(f"[bold red][!] Error:[/bold red] {error}")

    def option_help(self) -> None:
        """
        Displays help information for the available options.
        """
        self.console.print("[bold blue]DirectoryBruteforcer Options:[/bold blue]")
        table = Table(box=box.SIMPLE)
        table.add_column("[bold]Option[/bold]")
        table.add_column("[bold]Description[/bold]")
        table.add_column("[bold]Default[/bold]")
        for option, help_text in self.options_help.items():
            default_value = self.options.get(option)
            if default_value is None and option == "wordlist":
                default_value = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            elif default_value is None and option == "threads":
                default_value = "20"
            elif default_value is None and option == "timeout":
                default_value = "10"
            elif default_value is None and option == "depth":
                default_value = "1"
            elif default_value is None and option == "status_codes":
                default_value = "200,204,301,302,307,401,403"
            elif default_value is None and option == "silent":
                default_value = "False"
            elif default_value is None and option == "output":
                default_value = "None"

            table.add_row(option, help_text, str(default_value))
        self.console.print(table)