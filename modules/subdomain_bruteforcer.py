import subprocess
import shutil
from rich.console import Console
from rich.table import Table
from rich import box
from typing import Dict, List, Optional, Union, Any

class SubdomainBruteforcer:
    """
    A module for performing subdomain enumeration on a target domain using Gobuster.
    Provides enhanced output formatting and result handling.
    """

    def __init__(self, options: Optional[Dict[str, str]] = None):
        """
        Initializes the SubdomainBruteforcer with optional configuration.

        Args:
            options (Optional[Dict[str, str]]): Configuration dictionary.
                Supported keys: 'domain', 'wordlist', 'output'.
        """
        self.console = Console()
        self.options_help = {
            "domain": "Target domain to enumerate (required).",
            "wordlist": "Path to wordlist for subdomain bruteforcing (default: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt).",
            "output": "Optional path to save found subdomains.",
        }
        self.options = options or {}
        self.results: Dict[str, Union[List[str], int, List[str]]] = {
            "found_subdomains": [],
            "total_found": 0,
            "errors": []
        }
        if not shutil.which("gobuster"):
            raise EnvironmentError("gobuster is not installed or not in PATH.")

    def run(self) -> Dict[str, Any]:
        """
        Executes the subdomain bruteforce scan using Gobuster.

        Returns:
            Dict[str, Any]: Results dictionary including found subdomains, count, and errors.
        """
        domain = self.options.get("domain", "").strip()
        wordlist = self.options.get("wordlist", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        output_path = self.options.get("output")

        if not domain:
            self.results["errors"].append("Target domain is required.")
            self._display_errors()
            return self.results

        self.console.print(f"[bold blue]Starting subdomain bruteforce on:[/bold blue] [green]{domain}[/green]")
        self.console.print(f"[bold blue]Using wordlist:[/bold blue] [yellow]{wordlist}[/yellow]\n")

        cmd = [
            "gobuster", "dns",
            "-d", domain,
            "-w", wordlist,
            "-q"
        ]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            while True:
                line = process.stdout.readline()
                if not line:
                    break
                line = line.strip()

                if line:
                    # print(f"printing line: {line}")
                    self.console.print(f"[green][✅]{line[4:]}[/green]")
                    if "Found:" in line:
                        url = line.split("Found:")[1].strip()
                        self.results["found_subdomains"].append(url)

            stdout, stderr = process.communicate()
            if process.returncode != 0:
                self.results["errors"].append(f"Gobuster error: {stderr.strip()}")
            elif stderr.strip():
                self.console.print(f"[yellow]Gobuster messages:[/yellow] [dim]{stderr.strip()}[/dim]")

            self.results["total_found"] = len(self.results["found_subdomains"])
            self._display_results()

            if output_path:
                with open(output_path, "w") as f:
                    for sub in self.results["found_subdomains"]:
                        f.write(f"{sub}\n")
                self.console.print(f"\n[bold green]Results saved to:[/bold green] [yellow]{output_path}[/yellow]")

        except FileNotFoundError:
            self.results["errors"].append("Error: The specified wordlist file was not found.")
            self._display_errors()
        except subprocess.CalledProcessError as e:
            self.results["errors"].append(f"Gobuster error: {e}")
            self._display_errors()
        except Exception as e:
            self.results["errors"].append(f"An unexpected error occurred: {e}")
            self._display_errors()

        return self.results

    def _display_results(self):
        """
        Displays the discovered subdomains in a formatted table.
        """
        if self.results["found_subdomains"]:
            self.console.print("\n[bold green]--- Discovered Subdomains ---[/bold green]")
            table = Table(title="Subdomain Results", box=box.SIMPLE)
            table.add_column("[bold blue]Subdomain[/bold blue]")

            for sub in sorted(self.results["found_subdomains"]):
                table.add_row(sub)

            self.console.print(table)
            self.console.print(f"\n[bold green]Total Found:[/bold green] [cyan]{self.results['total_found']}[/cyan]")
        else:
            self.console.print("\n[bold yellow]No subdomains found with the given wordlist.[/bold yellow]")

    def _display_errors(self):
        """
        Displays any errors encountered during execution.
        """
        if self.results["errors"]:
            self.console.print("\n[bold red]--- Errors ---[/bold red]")
            for error in self.results["errors"]:
                self.console.print(f"[bold red][!] Error:[/bold red] {error}")

    def option_help(self) -> None:
        """
        Displays available options and their descriptions.
        """
        self.console.print("[bold blue]SubdomainBruteforcer Options:[/bold blue]")
        table = Table(box=box.SIMPLE)
        table.add_column("[bold]Option[/bold]")
        table.add_column("[bold]Description[/bold]")
        table.add_column("[bold]Default[/bold]")

        for option, help_text in self.options_help.items():
            default_value = self.options.get(option)
            if default_value is None:
                if option == "wordlist":
                    default_value = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                else:
                    default_value = "None"
            table.add_row(option, help_text, str(default_value))
        self.console.print(table)
