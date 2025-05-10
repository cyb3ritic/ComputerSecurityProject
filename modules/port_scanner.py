from core.scanner import BaseScanner
import subprocess
import socket
import re
import json
from datetime import datetime
import concurrent.futures
import threading
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel

console = Console()

class PortScanner(BaseScanner):

    def __init__(self, options=None):
        super().__init__()

        self.options_help = {
        "target": "The target IP address or hostname to scan.",
        "ports": "Comma-separated list of ports to scan (e.g., 80,443,8080) or ranges (e.g., 1-1000).",
        "mode": "Scan mode: quick, detailed, custom, stealth, or service.",
        "timeout": "Connection timeout in seconds (default: 1).",
        "threads": "Number of concurrent threads for scanning (default: 10).",
        "output": "Output file path to save results (optional).",
        "nmap_flags": "Custom Nmap flags to use in 'custom' mode.",
        "show_closed": "Show closed ports in results (default: False)."
        }
        self.results = {
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {},
            "banners": {},
            "versions": {}
        }
        self.start_time = None
        self.end_time = None
        # Add locks to prevent race conditions in concurrent operations
        self.results_lock = threading.Lock()
        
    def validate_options(self):
        if "target" not in self.options:
            raise ValueError("Target is required.")

        # Validate target
        try:
            socket.gethostbyname(self.options["target"])
        except socket.gaierror:
            raise ValueError(f"Invalid target: {self.options['target']}")

        # Set default options
        self.options.setdefault("ports", "1-1000")
        self.options.setdefault("mode", "quick")
        self.options.setdefault("timeout", 1)
        self.options.setdefault("threads", 10)
        self.options.setdefault("show_closed", False)

        # Convert numeric options to appropriate types
        try:
            self.options["timeout"] = float(self.options["timeout"])
            self.options["threads"] = int(self.options["threads"])
            if isinstance(self.options["show_closed"], str):
                self.options["show_closed"] = self.options["show_closed"].lower() in ["true", "yes", "1"]
        except ValueError:
            raise ValueError("Timeout must be a number and threads must be an integer.")

    def parse_ports(self, ports_str):
        ports = set()
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start > end:
                        console.print(f"[yellow]Warning: Invalid port range {start}-{end}, skipping[/yellow]")
                        continue
                    ports.update(range(max(1, start), min(end, 65535) + 1))
                except ValueError:
                    console.print(f"[yellow]Warning: Invalid port range format '{part}', skipping[/yellow]")
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                    else:
                        console.print(f"[yellow]Warning: Port {port} out of range (1-65535), skipping[/yellow]")
                except ValueError:
                    console.print(f"[yellow]Warning: Invalid port number '{part}', skipping[/yellow]")
        
        return sorted(list(ports))

    def check_port(self, target, port):
        # Use threading.Lock to prevent race conditions when updating results
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.options["timeout"])
                result = s.connect_ex((target, port))
                
                # Synchronize updates to the results dictionary
                with self.results_lock:
                    if result == 0:
                        # Port is open
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except OSError:
                            service = "unknown"
                        
                        # Avoid adding duplicates - with proper synchronization
                        if port not in self.results["open_ports"]:
                            self.results["open_ports"].append(port)
                            self.results["services"][port] = service
                        
                        # Try to grab banner (outside the lock to avoid holding it during I/O)
                
                # Get banner outside the lock if the port is open
                if result == 0 and port not in self.results["banners"]:
                    banner = self.banner_grab(target, port)
                    if banner:
                        # Lock again to update banners
                        with self.results_lock:
                            self.results["banners"][port] = banner
                
                # Update other result categories with proper locking
                with self.results_lock:
                    if result == 111 or result == 10061:  # Connection refused
                        if port not in self.results["closed_ports"]:
                            self.results["closed_ports"].append(port)
                    elif result != 0:  # Not open and not explicitly closed
                        if port not in self.results["filtered_ports"]:
                            self.results["filtered_ports"].append(port)
                    
                return result
        except Exception as e:
            with self.results_lock:
                if port not in self.results["filtered_ports"]:
                    self.results["filtered_ports"].append(port)
            return -1

    def banner_grab(self, target, port):
        common_probes = {
            21: b"USER anonymous\r\n",  # FTP
            22: b"SSH-2.0-OpenSSH_8.0\r\n",  # SSH
            25: b"HELO example.com\r\n",  # SMTP
            80: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",  # HTTP
            443: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",  # HTTPS
            110: b"USER anonymous\r\n",  # POP3
            143: b"a001 CAPABILITY\r\n",  # IMAP
            3306: b"\x19\x00\x00\x00\x0a",  # MySQL
            5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL
        }
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                
                # Send appropriate probe if available
                if port in common_probes:
                    try:
                        s.send(common_probes[port])
                    except:
                        pass
                else:
                    # Generic probe
                    try:
                        s.send(b"\r\n")
                    except:
                        pass
                
                # Receive response
                try:
                    banner = s.recv(1024)
                    return banner.decode('utf-8', errors='replace').strip()
                except:
                    return None
        except:
            return None

    def guess_service_version(self, banner, port):
        if not banner:
            return "unknown"
            
        version_patterns = {
            "nginx": r"nginx/(\d+\.\d+\.\d+)",
            "apache": r"apache[/ ](\d+\.\d+\.\d+)",
            "openssh": r"openssh[_-](\d+\.\d+\w*)",
            "mysql": r"mysql[_-](\d+\.\d+\.\d+)",
            "ftp": r"ftp[/ ](\d+\.\d+\.\d+)",
            "smtp": r"smtp[/ ](\d+\.\d+\.\d+)",
            "http": r"http[/ ](\d+\.\d+)",
        }
        
        banner_lower = banner.lower()
        for service, pattern in version_patterns.items():
            match = re.search(pattern, banner_lower)
            if match:
                return f"{service} {match.group(1)}"
        
        # Common service guesses based on port
        port_to_service = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB"
        }
        
        if port in port_to_service:
            return f"{port_to_service[port]} (banner captured)"
            
        return "unknown service"

    def scan_ports(self, target, ports):
        # We now initialize results in the run() method
        console.print(f"[bold green][+] Scanning {len(ports)} ports on {target}...[/bold green]")
        
        # Ensure we're scanning each port only once - use a set for uniqueness
        unique_ports = list(set(ports))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        ) as progress:
            task = progress.add_task("[green]Scanning ports", total=len(unique_ports))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.options["threads"]) as executor:
                # Map each port to a future that will scan it
                futures_to_ports = {executor.submit(self.check_port, target, port): port for port in unique_ports}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(futures_to_ports):
                    port = futures_to_ports[future]
                    
                    try:
                        result = future.result()
                        # If port is open, process banner and determine version
                        if result == 0:  # Open port
                            banner = self.results["banners"].get(port)
                            if banner:
                                version = self.guess_service_version(banner, port)
                                # Synchronize version updates
                                with self.results_lock:
                                    self.results["versions"][port] = version
                    except Exception as e:
                        console.print(f"[red]Error scanning port {port}: {str(e)}[/red]")
                    
                    progress.update(task, advance=1)

    def run_command(self, command, timeout=60):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
            if result.returncode != 0 and result.stderr:
                return f"Error: {result.stderr.strip()}"
            return result.stdout.strip() or result.stderr.strip()
        except subprocess.TimeoutExpired:
            return f"Command timed out after {timeout} seconds"
        except Exception as e:
            return f"Error executing command: {str(e)}"

    def check_nmap_installed(self):
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def nmap_scan(self, target, mode):
        if not self.check_nmap_installed():
            console.print("[red][!] Nmap is not installed or not in PATH. Skipping Nmap scan.[/red]")
            return "Nmap not available"
            
        nmap_modes = {
            "quick": ["-F"],
            "detailed": ["-A", "-T4"],
            "stealth": ["-sS", "-T2"],
            "service": ["-sV", "--version-intensity", "2"],
            "custom": self.options.get("nmap_flags", "-A -p-").split(),
        }
        
        flags = nmap_modes.get(mode, ["-F"])
        if not isinstance(flags, list):
            flags = flags.split()
            
        ports_str = ",".join(str(p) for p in self.results["open_ports"]) if self.results["open_ports"] else "1-1000"
        
        command = ["nmap"] + flags + ["-p", ports_str, target]
        console.print(f"[dim]Running: {' '.join(command)}[/dim]")
        
        result = self.run_command(command, timeout=500)
        return result

    def print_results(self, ip):
        console.print(Panel(f"[bold]SCAN RESULTS FOR {ip}[/bold]", border_style="green"))
        
        # Summary
        open_count = len(self.results["open_ports"])
        closed_count = len(self.results["closed_ports"])
        filtered_count = len(self.results["filtered_ports"])
        
        console.print(f"[green]Open ports: {open_count}[/green]")
        console.print(f"[red]Closed ports: {closed_count}[/red]")
        console.print(f"[yellow]Filtered ports: {filtered_count}[/yellow]")
        
        # Open ports table
        if open_count > 0:
            table = Table(title="Open Ports Detail")
            table.add_column("Port", justify="right", style="cyan", no_wrap=True)
            table.add_column("Service", style="green")
            table.add_column("Version/Info", style="yellow")
            table.add_column("Banner", style="blue")
            
            for port in sorted(self.results["open_ports"]):
                service = self.results["services"].get(port, "unknown")
                version = self.results["versions"].get(port, "")
                banner = self.results["banners"].get(port, "")
                
                # Truncate banner if it's too long
                if banner and len(banner) > 50:
                    banner = banner[:47] + "..."
                    
                table.add_row(str(port), service, version, banner)
                
            console.print(table)
        else:
            console.print("[yellow]No open ports found.[/yellow]")
        
        # Closed ports (optional)
        if self.options["show_closed"] and closed_count > 0:
            closed_table = Table(title="Closed Ports")
            closed_table.add_column("Port", justify="right", style="dim")
            
            # Show first 10 closed ports
            for port in sorted(self.results["closed_ports"])[:10]:
                closed_table.add_row(str(port))
                
            if closed_count > 10:
                closed_table.add_row(f"... and {closed_count - 10} more")
                
            console.print(closed_table)

    def export_results(self, target, ip):
        output_file = self.options.get("output")
        if not output_file:
            return

        result_data = {
            "target": target,
            "ip": ip,
            "scan_time": str(datetime.now()),
            "scan_duration": str(self.end_time - self.start_time),
            "scan_options": self.options,
            "open_ports": sorted(self.results["open_ports"]),
            "closed_ports": sorted(self.results["closed_ports"]),
            "filtered_ports": sorted(self.results["filtered_ports"]),
            "services": self.results["services"],
            "versions": self.results["versions"],
            "banners": self.results["banners"],
        }

        try:
            with open(output_file, "w") as f:
                json.dump(result_data, f, indent=4)
            console.print(f"[bold cyan][+] Results saved to {output_file}[/bold cyan]")
        except Exception as e:
            console.print(f"[red][!] Failed to save results: {e}[/red]")

    def run(self):
        self.start_time = datetime.now()
        console.print(Panel("[bold]PORT SCANNER[/bold]", border_style="magenta"))
        
        try:
            self.validate_options()
        except ValueError as e:
            console.print(f"[red][!] {e}[/red]")
            return

        target = self.options["target"]
        ports_str = self.options["ports"]
        mode = self.options["mode"]

        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                console.print(f"[green][+] Resolved {target} to {ip}[/green]")
        except socket.gaierror:
            console.print(f"[red][!] Could not resolve hostname: {target}[/red]")
            return
            
        # Parse port specification
        ports = self.parse_ports(ports_str)
        if not ports:
            console.print("[red][!] No valid ports specified[/red]")
            return
            
        # Initialize results to empty to avoid any previous data
        self.results = {
            "open_ports": [],
            "closed_ports": [],
            "filtered_ports": [],
            "services": {},
            "banners": {},
            "versions": {}
        }
            
        # Run the scan
        try:
            self.scan_ports(ip, ports)
            self.print_results(ip)

            # Run Nmap if requested
            if mode in ["detailed", "stealth", "service", "custom"]:
                console.print(f"\n[yellow][*] Running Nmap scan with mode: {mode}[/yellow]")
                nmap_output = self.nmap_scan(ip, mode)
                self.print_section("NMAP SCAN RESULTS", nmap_output)

            # Export if requested
            self.export_results(target, ip)
            
        except KeyboardInterrupt:
            console.print("\n[bold red][!] Scan interrupted by user[/bold red]")
        except Exception as e:
            console.print(f"\n[bold red][!] Error during scan: {str(e)}[/bold red]")
            import traceback
            console.print(traceback.format_exc())
        finally:
            self.end_time = datetime.now()
            duration = self.end_time - self.start_time
            console.print(f"[bold green][✓] Scan completed in {duration}[/bold green]")

    def print_section(self, title, content):
        console.print(f"\n[bold magenta]{title}[/bold magenta]\n{'=' * len(title)}")
        if content:
            console.print(content)
        else:
            console.print("[italic]No output available.[/italic]")