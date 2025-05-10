import os
import sys
import re
import json
import socket
import datetime
import ipaddress
import subprocess # Kept for specific cases if BaseScanner.run_command is not sufficient, but aim to use BaseScanner's
from typing import Dict, List, Tuple, Optional, Any, Union

# Assuming BaseScanner is in core.scanner and core is in PYTHONPATH
from core.scanner import BaseScanner
# from termcolor import colored # Provided by BaseScanner

# Attempt to import netifaces for interface validation, but make it optional
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

class NetworkScanner(BaseScanner):
    """Network discovery and information gathering module"""

    def __init__(self):
        super().__init__() # Initialize BaseScanner
        self.name = "NetworkScanner" # Helpful for logging or messages

        self.scan_tools = {
            "ping": "Check if hosts are up using ICMP echo requests",
            "arp": "Discover hosts on local network using ARP requests (requires root/admin)",
            "dns": "Perform DNS lookups (A, MX, NS, CNAME, etc.)",
            "whois": "Query WHOIS information for domains or IP addresses",
            "traceroute": "Trace the route packets take to a host",
            "all": "Run all available network discovery tools"
        }

        # Default options are set in BaseScanner or can be overridden here if needed
        # For PentestConsole, options are typically set via `set <option> <value>`
        # We define their existence and help text in options_help
        # self.options = {} # This will be populated by PentestConsole

        self.options_help = {
            "target": ("Target IP, hostname, domain, or CIDR range (e.g., 192.168.1.0/24).", None),
            "scan_type": ("Type of network scan to perform.", list(self.scan_tools.keys())),
            "output_file": ("File to save the scan results (e.g., scan_results_net.json). Extension will be added if missing.", None),
            "timeout": ("Scan timeout in seconds for each command (e.g., 60).", ["10", "30", "60", "120", "300"]),
            "dns_type": ("DNS record type(s) to query, comma-separated or ALL (e.g., A,MX or ALL).", ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR", "SRV", "ALL"]),
            "interface": ("Network interface to use (e.g., eth0, en0 - for ARP scan).", None), # Dynamic list would be complex here
            "show_live_output": ("Show live output during scan.", ["true", "false"]),
            "ping_packets": ("Number of packets for ping scan (default 2).", ["1","2","3","4"]),
        }

        self.required_options = ["target"] # scan_type defaults to 'all' if not provided by user through 'set'

        self.required_commands_by_type = {
            "ping": ["ping"],
            "arp": ["arp-scan"], # arp-scan is Linux specific mostly
            "dns": ["dig", "nslookup"], # Need at least one
            "whois": ["whois"],
            "traceroute": ["traceroute", "tracert"], # Need at least one
        }
        
        # Default values if not set by user
        self._default_options = {
            "scan_type": "all",
            "timeout": "60",
            "dns_type": "ALL",
            "interface": "",
            "show_live_output": "true",
            "ping_packets": "2",
            "output_file": ""
        }


    def _get_option(self, key: str) -> Any:
        """Helper to get option value or its default."""
        return self.options.get(key, self._default_options.get(key))


    def validate_options(self) -> Tuple[bool, str]:
        """Validate the options for this scanner"""
        # Check required options
        for option_name in self.required_options:
            if not self._get_option(option_name): # Check if target is provided
                return False, f"Missing required option: {option_name}"

        scan_type = self._get_option("scan_type")
        if scan_type not in self.scan_tools:
            return False, f"Invalid scan type: {scan_type}. Available types: {', '.join(self.scan_tools.keys())}"

        # Check required commands
        scan_types_to_check_commands = []
        if scan_type == "all":
            scan_types_to_check_commands = [st for st in self.scan_tools if st != "all"]
        else:
            scan_types_to_check_commands = [scan_type]

        missing_tool_message = ""
        found_at_least_one_tool_for_all = False

        for st_check in scan_types_to_check_commands:
            req_cmds_options = self.required_commands_by_type.get(st_check, [])
            if not req_cmds_options: continue # No specific command needed for this type (unlikely here)

            cmd_found = any(self.check_command_exists(cmd) for cmd in req_cmds_options)

            if not cmd_found:
                tool_names = "/".join(req_cmds_options)
                msg = f"Missing required command(s) for '{st_check}' scan: please install one of [{tool_names}]. "
                if scan_type == "all":
                    missing_tool_message += msg
                else: # Specific scan type chosen but tool missing
                    return False, msg.strip()
            else:
                found_at_least_one_tool_for_all = True

        if scan_type == "all" and not found_at_least_one_tool_for_all and not missing_tool_message:
             # This case means 'all' was selected, but no specific tools were defined in required_commands_by_type
             # Or, more likely, all defined tools were checked and found.
             # If no tools were found AT ALL for 'all' scan:
            if not any(any(self.check_command_exists(cmd) for cmd in self.required_commands_by_type.get(st, [])) for st in self.scan_tools if st != "all"):
                return False, "No network scanning tools (ping, arp-scan, dig/nslookup, whois, traceroute/tracert) found. Please install required tools."
        elif scan_type == "all" and missing_tool_message and not found_at_least_one_tool_for_all:
             # If 'all' was selected, and for every type of scan, at least one command was missing.
            return False, f"For 'all' scan type, no tools found. Issues: {missing_tool_message.strip()}"


        target = self._get_option("target")
        # Basic target validation (more specific validation can be per-scan-type)
        if not target.strip():
            return False, "Target cannot be empty."

        # Validate DNS type
        if scan_type == "dns" or scan_type == "all":
            dns_types_str = self._get_option("dns_type").upper()
            valid_dns_options = self.options_help["dns_type"][1] # Get from options_help
            if dns_types_str != "ALL":
                for dt in dns_types_str.split(','):
                    if dt.strip() not in valid_dns_options:
                        return False, f"Invalid DNS record type: {dt}. Valid types: {', '.join(valid_dns_options)}"
        
        # Validate timeout
        try:
            timeout = int(self._get_option("timeout"))
            if timeout <= 0:
                return False, "Timeout must be a positive integer."
        except ValueError:
            return False, "Timeout must be a valid integer."

        # Validate ping_packets
        try:
            ping_packets = int(self._get_option("ping_packets"))
            if not 0 < ping_packets <= 10: # Max 10 packets
                return False, "Ping packets must be between 1 and 10."
        except ValueError:
            return False, "Ping packets must be a valid integer."


        # Validate interface if specified (especially for ARP)
        interface = self._get_option("interface")
        if interface:
            if not self.validate_interface(interface):
                # If netifaces not available, this will return True with a warning printed by validate_interface
                # If netifaces is available and returns false, then it's an invalid interface
                if NETIFACES_AVAILABLE: # Only fail if netifaces could actually check
                    return False, f"Invalid or non-existent network interface: {interface}"
        
        if scan_type == "arp":
            if not interface:
                self.print_warning("For ARP scan, specifying a network interface with 'set interface <iface>' is highly recommended.")
            # ARP scan is for local networks. Warn if target looks like a public domain/IP.
            try:
                ipaddress.ip_address(target) # Check if it's an IP
            except ValueError: # If it's a hostname
                if not (target.lower() == "localhost" or ".local" in target.lower()): # very basic check
                    # Attempt to resolve to see if it's local, this is imperfect
                    try:
                        ip_addr = socket.gethostbyname(target)
                        if not ipaddress.ip_address(ip_addr).is_private:
                            self.print_warning(f"Target '{target}' ({ip_addr}) for ARP scan appears to be non-local. ARP scans are for local networks.")
                    except socket.gaierror:
                        self.print_warning(f"Could not resolve target '{target}' to check if it's local for ARP scan.")


        return True, "Options validated successfully"

    def validate_interface(self, interface_name: str) -> bool:
        """Check if the specified network interface exists."""
        if not NETIFACES_AVAILABLE:
            self.print_warning("Python 'netifaces' library not found. Cannot validate network interface. Assuming it's correct if specified.")
            return True # Cannot validate, so assume true to not block
        try:
            if interface_name in netifaces.interfaces():
                return True
            else:
                self.print_error(f"Interface '{interface_name}' not found. Available interfaces: {', '.join(netifaces.interfaces())}")
                return False
        except Exception as e:
            self.print_error(f"Error validating interface '{interface_name}': {e}")
            return False # Error during validation

    def _determine_scan_tool(self, tool_category: str) -> Optional[str]:
        """Determines the specific command to use, e.g., 'dig' or 'nslookup'."""
        possible_cmds = self.required_commands_by_type.get(tool_category, [])
        for cmd in possible_cmds:
            if self.check_command_exists(cmd):
                return cmd
        return None

    def run(self) -> str:
        """
        Main entry point for PentestConsole.
        Validates options, runs the scan, and returns a summary string.
        """
        self.print_info(f"Initializing {self.name}...")

        # Merge provided options with defaults
        # self.options will be populated by PentestConsole's `set` commands.
        # We need to ensure all keys used by _get_option are available.
        current_options = self.options.copy() # From PentestConsole
        for key, default_value in self._default_options.items():
            if key not in current_options:
                 current_options[key] = default_value
        self.options = current_options # Update self.options to include defaults for this run


        is_valid, message = self.validate_options()
        if not is_valid:
            self.print_error(f"Option validation failed: {message}")
            return f"{self.name} aborted: {message}"

        scan_type_display = self._get_option("scan_type")
        self.print_info(f"Starting {scan_type_display} scan for target: {self._get_option('target')}")
        
        start_time = datetime.datetime.now()
        detailed_results = self._perform_scan_logic(start_time)
        end_time = datetime.datetime.now()
        
        detailed_results["duration"] = str(end_time - start_time)
        detailed_results["end_time"] = end_time.isoformat()

        # Save results if output file specified
        output_file_name = self._get_option("output_file")
        if output_file_name:
            # Use the save_results from BaseScanner by passing the filename
            # Or use a local one if specific formatting needed
            self.scan_results = detailed_results # Ensure BaseScanner.save_results uses this
            if not output_file_name.lower().endswith(('.json', '.txt')): # Ensure .json for detailed dict
                output_file_name += ".json"
            if super().save_results(output_file_name): # Calls BaseScanner's save_results
                self.print_success(f"Detailed results saved to {output_file_name}")
            else:
                self.print_error(f"Failed to save detailed results to {output_file_name}")

        # Generate summary string
        summary = f"{self.name} ({scan_type_display} for {self._get_option('target')}) "
        if detailed_results.get("error"):
            summary += f"completed with errors: {detailed_results['error']}. "
        elif not detailed_results.get("results"): # No actual results and no top-level error
            summary += "completed, but no specific results were generated (check tool availability or target). "
        else:
            summary += "completed. "
            # Add more specific counts if available
            if "ping" in detailed_results["results"] and "alive_hosts" in detailed_results["results"]["ping"]:
                summary += f"Ping: {len(detailed_results['results']['ping']['alive_hosts'])} alive. "
            if "arp" in detailed_results["results"] and "hosts" in detailed_results["results"]["arp"]:
                summary += f"ARP: {len(detailed_results['results']['arp']['hosts'])} found. "
            if "dns" in detailed_results["results"] and "records" in detailed_results["results"]["dns"]:
                dns_record_count = sum(len(v) for k,v in detailed_results["results"]["dns"]["records"].items() if isinstance(v,list))
                summary += f"DNS: {dns_record_count} records found. "
            if "whois" in detailed_results["results"] and detailed_results["results"]["whois"].get("parsed"):
                summary += f"WHOIS: Parsed. "
            if "traceroute" in detailed_results["results"] and "hops" in detailed_results["results"]["traceroute"]:
                 summary += f"Traceroute: {len(detailed_results['results']['traceroute']['hops'])} hops. "
        
        if output_file_name:
            summary += f"Full results in {output_file_name}."

        return summary.strip()

    def _perform_scan_logic(self, scan_start_time: datetime.datetime) -> Dict[str, Any]:
        """Internal method to run the network scan based on configured options"""
        # Initialize scan results structure for this specific scan
        current_scan_results = {
            "start_time": scan_start_time.isoformat(),
            "end_time": "", # Will be filled at the end
            "duration": "", # Will be filled at the end
            "target": self._get_option("target"),
            "scan_type_performed": self._get_option("scan_type"),
            "options_used": self.options.copy(), # Log the options used for this scan
            "results": {} # Sub-results per tool
        }
        
        try:
            scan_types_to_run = []
            selected_scan_type = self._get_option("scan_type")

            if selected_scan_type == "all":
                for tool_cat in self.scan_tools:
                    if tool_cat == "all": continue
                    # Check if tools for this category are available
                    tool_cmd = self._determine_scan_tool(tool_cat)
                    if tool_cmd:
                        scan_types_to_run.append(tool_cat)
                    elif self._get_option("show_live_output") == "true":
                        self.print_warning(f"Skipping '{tool_cat}' scan in 'all' mode: No required tool found.")
            else:
                # Check if tool for specific scan type is available
                tool_cmd = self._determine_scan_tool(selected_scan_type)
                if tool_cmd:
                    scan_types_to_run.append(selected_scan_type)
                else:
                    missing_cmds = "/".join(self.required_commands_by_type.get(selected_scan_type, ["unknown tool"]))
                    current_scan_results["error"] = f"Required tool ({missing_cmds}) for '{selected_scan_type}' scan not found."
                    self.print_error(current_scan_results["error"])
                    return current_scan_results # Early exit if specific scan tool is missing

            if not scan_types_to_run:
                msg = "No scan types to run (tools might be missing or not specified)."
                current_scan_results["error"] = msg
                self.print_warning(msg)
                return current_scan_results

            for scan_type_item in scan_types_to_run:
                self.print_info(f"Running {scan_type_item} scan...")
                if scan_type_item == "ping":
                    current_scan_results["results"]["ping"] = self.run_ping_scan()
                elif scan_type_item == "arp":
                    current_scan_results["results"]["arp"] = self.run_arp_scan()
                elif scan_type_item == "dns":
                    current_scan_results["results"]["dns"] = self.run_dns_scan()
                elif scan_type_item == "whois":
                    current_scan_results["results"]["whois"] = self.run_whois_scan()
                elif scan_type_item == "traceroute":
                    current_scan_results["results"]["traceroute"] = self.run_traceroute_scan()
            
        except Exception as e:
            current_scan_results["error"] = f"General scan failure: {str(e)}"
            self.print_error(current_scan_results["error"])
        
        return current_scan_results

    def run_ping_scan(self) -> Dict[str, Any]:
        target = self._get_option("target")
        timeout_val = int(self._get_option("timeout"))
        num_packets = self._get_option("ping_packets") # String, validated as int
        show_live = self._get_option("show_live_output") == "true"

        results: Dict[str, Any] = { "command_used": "", "output_log": "", "alive_hosts": [], "unreachable_hosts": [], "errors": [] }
        
        try:
            ip_list = []
            try:
                # Check if target is CIDR
                network = ipaddress.ip_network(target, strict=False)
                num_hosts = network.num_addresses
                if num_hosts > 2**12 and not (network.is_loopback or network.is_private) : # More than 4096 hosts for public CIDR
                    self.print_warning(f"Target CIDR {target} ({num_hosts} addresses) is very large. Ping scan might take a long time.")
                # For very large networks, consider sampling or alternative methods not implemented here.
                # Here, we'll ping all hosts as per original logic.
                ip_list = [str(host) for host in network.hosts()]
                if not ip_list and num_hosts > 2 : # e.g. /31, /32
                     ip_list = [str(addr) for addr in network]


            except ValueError: # Not a CIDR, treat as single host/domain
                ip_list = [target]

            if not ip_list:
                results["errors"].append(f"No valid IP addresses derived from target '{target}'.")
                return results

            ping_cmd_base = []
            if sys.platform == "win32":
                # -w timeout in milliseconds
                ping_cmd_base = ["ping", "-n", num_packets, "-w", str(timeout_val * 1000)]
            else: # Linux/MacOS
                # -W timeout in seconds (for response), -w deadline (total time, also in seconds)
                # Using -W for per-packet timeout, subprocess timeout for overall.
                ping_cmd_base = ["ping", "-c", num_packets, "-W", str(timeout_val)]
            
            results["command_used"] = "ping [...] " + target

            for host_target in ip_list:
                current_cmd = ping_cmd_base + [host_target]
                stdout, stderr, returncode = self.run_command(current_cmd, timeout=timeout_val + 5) # subprocess timeout
                
                log_entry = f"\n=== Pinging {host_target} ===\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nReturn Code: {returncode}\n"
                results["output_log"] += log_entry

                if returncode == 0: # Success varies by OS, but 0 is usually good
                    # Further check stdout for reliability (e.g., "Request timed out" can still yield rc 0 on some pings if some packets get through)
                    if "ttl=" in stdout.lower() or "bytes from" in stdout.lower(): # Common success indicators
                        results["alive_hosts"].append(host_target)
                        if show_live: self.print_success(f"Host {host_target} is ALIVE.")
                    else: # RC 0 but output doesn't look like a success
                        results["unreachable_hosts"].append(host_target)
                        if show_live: self.print_warning(f"Host {host_target} (RC 0) reported no TTL/response, likely UNREACHABLE.")
                elif "command timed out" in stderr.lower() and returncode == -1 : # From BaseScanner.run_command
                    results["unreachable_hosts"].append(host_target)
                    if show_live: self.print_warning(f"Host {host_target} PING TIMED OUT (command execution).")
                else:
                    results["unreachable_hosts"].append(host_target)
                    if show_live: self.print_error(f"Host {host_target} is UNREACHABLE (RC:{returncode}).")
        
        except Exception as e:
            err_msg = f"Ping scan failed: {str(e)}"
            results["errors"].append(err_msg)
            self.print_error(err_msg)
        return results

    def run_arp_scan(self) -> Dict[str, Any]:
        target = self._get_option("target")
        interface = self._get_option("interface")
        timeout_val = int(self._get_option("timeout"))
        show_live = self._get_option("show_live_output") == "true"
        results: Dict[str, Any] = { "command_used": "", "output_log": "", "hosts": [], "errors": [] }

        arp_tool = self._determine_scan_tool("arp")
        if not arp_tool:
            results["errors"].append("arp-scan tool not found.")
            return results
        
        if arp_tool == "arp-scan": # Primarily Linux
            cmd = [arp_tool, "--quiet"] # Reduce verbosity from arp-scan itself
            if interface:
                cmd.extend(["-I", interface])
            
            # arp-scan timeout is in milliseconds for the entire scan duration for discovered hosts.
            # The run_command timeout will act as a hard cap.
            cmd.extend(["--timeout", str(timeout_val * 1000)]) 
            cmd.append(target) # Target can be IP, CIDR, or interface name (arp-scan specific)
            results["command_used"] = " ".join(cmd)

            stdout, stderr, returncode = self.run_command(cmd, timeout=timeout_val + 10) # Give arp-scan time
            results["output_log"] = f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}\nReturn Code: {returncode}"

            if returncode == 0:
                # Example arp-scan output line: "192.168.1.1   00:11:22:33:44:55   Vendor Name"
                #                           "192.168.1.10  (Unknown)"  -- if MAC not resolved
                #                           "192.168.1.1   b8:27:eb:3d:4a:5b   Raspberry Pi Foundation"
                pattern = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:]{17})\s*(.*)$")
                for line in stdout.splitlines():
                    match = pattern.match(line.strip())
                    if match:
                        ip, mac, vendor = match.groups()
                        host_info = {"ip": ip.strip(), "mac": mac.strip(), "vendor": vendor.strip()}
                        results["hosts"].append(host_info)
                        if show_live: self.print_success(f"ARP: Found {ip} ({mac}) - {vendor}")
            elif "command timed out" in stderr.lower() and returncode == -1:
                 results["errors"].append("ARP scan command timed out.")
            elif stderr:
                 results["errors"].append(f"ARP scan error: {stderr.strip()}")

            if not results["hosts"] and not results["errors"]:
                 results["errors"].append("No hosts discovered via ARP or error in output.")

        else: # Placeholder for other OS or arp tools if added
            results["errors"].append(f"ARP scan on this OS/with {arp_tool} not fully implemented.")
            self.print_warning(results["errors"][-1])
        return results

    def run_dns_scan(self) -> Dict[str, Any]:
        target = self._get_option("target")
        record_types_str = self._get_option("dns_type").upper()
        timeout_val = int(self._get_option("timeout"))
        show_live = self._get_option("show_live_output") == "true"
        results: Dict[str, Any] = { "commands_used": [], "output_log": "", "records": {}, "errors": [] }

        dns_tool = self._determine_scan_tool("dns") # Prefers 'dig'
        if not dns_tool:
            results["errors"].append("No DNS query tool (dig/nslookup) found.")
            return results

        query_types_to_run = []
        if record_types_str == "ALL":
            query_types_to_run = [rt for rt in self.options_help["dns_type"][1] if rt != "ALL"]
        else:
            query_types_to_run = [rt.strip() for rt in record_types_str.split(',')]

        for q_type in query_types_to_run:
            cmd = []
            if dns_tool == "dig":
                cmd = ["dig", target, q_type, "+short", "+time=" + str(timeout_val // 2 if timeout_val > 2 else 1) , "+tries=1"] # dig timeout per try
            elif dns_tool == "nslookup": # nslookup timeout is harder to control precisely per query
                cmd = ["nslookup", f"-querytype={q_type}", target]
            
            if not cmd: continue
            results["commands_used"].append(" ".join(cmd))
            
            stdout, stderr, returncode = self.run_command(cmd, timeout=timeout_val)
            log_entry = f"\n=== Querying {q_type} for {target} using {dns_tool} ===\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nReturn Code: {returncode}\n"
            results["output_log"] += log_entry

            if returncode == 0:
                current_records = [line.strip() for line in stdout.splitlines() if line.strip() and not line.startswith(";") and "connection timed out" not in line.lower()]
                if current_records:
                    results["records"][q_type] = current_records
                    if show_live:
                        self.print_success(f"DNS {q_type} for {target}:")
                        for rec in current_records: self.print_info(f"  -> {rec}")
                elif "command timed out" in stderr.lower():
                     results["records"][q_type] = ["Query timed out"]
                else: # No records but no explicit error in stdout/stderr from run_command
                    results["records"][q_type] = ["No records found or non-authoritative response."]
            elif "command timed out" in stderr.lower() and returncode == -1:
                results["records"][q_type] = [f"Query for {q_type} timed out (tool execution)."]
                if show_live: self.print_warning(results["records"][q_type][0])
            else: # Error
                err_detail = stderr.strip() if stderr.strip() else "Unknown error"
                results["records"][q_type] = [f"Error querying {q_type}: {err_detail}"]
                if show_live: self.print_error(results["records"][q_type][0])
        
        if not results["records"] and not results["errors"]: # No records found for any type
            results["errors"].append(f"No DNS records found for target {target} with types {record_types_str}")

        return results

    def run_whois_scan(self) -> Dict[str, Any]:
        target = self._get_option("target")
        timeout_val = int(self._get_option("timeout"))
        show_live = self._get_option("show_live_output") == "true"
        results: Dict[str, Any] = { "command_used": "", "raw_output": "", "parsed_data": {}, "errors": [] }

        whois_tool = self._determine_scan_tool("whois")
        if not whois_tool:
            results["errors"].append("whois tool not found.")
            return results
        
        cmd = [whois_tool, target]
        results["command_used"] = " ".join(cmd)

        stdout, stderr, returncode = self.run_command(cmd, timeout=timeout_val)
        results["raw_output"] = stdout # Store full raw output

        if "command timed out" in stderr.lower() and returncode == -1:
            results["errors"].append("WHOIS command timed out.")
        elif returncode != 0 and "no match" not in stdout.lower() and "not found" not in stdout.lower(): # Some tools exit non-zero for "no match"
            err_msg = stderr.strip() if stderr.strip() else stdout.strip() # Errors can be in stdout for whois
            results["errors"].append(f"WHOIS lookup failed: {err_msg if err_msg else 'Unknown error, RC: '+str(returncode)}")
        elif "no match" in stdout.lower() or "not found" in stdout.lower():
            results["errors"].append(f"WHOIS: No match found for target '{target}'.")
        else: # Success or partial success
            # Basic parsing, WHOIS output is notoriously inconsistent
            parsed = {}
            common_fields = {
                "Domain Name": r"(?i)Domain Name:\s*(.+)",
                "Registrar": r"(?i)Registrar:\s*(.+)",
                "Creation Date": r"(?i)(Created|Creation Date|Activated):\s*(.+)",
                "Updated Date": r"(?i)(Updated|Last Updated):\s*(.+)",
                "Expiry Date": r"(?i)(Expires|Expiration Date|Expiry Date):\s*(.+)",
                "Name Server": r"(?i)(Name Server|Name Servers|Nserver):\s*(.+)",
                "Technical Contact": r"(?i)Technical Contact:\s*(.+)",
                "Status": r"(?i)(Status|Domain Status):\s*(.+)",
                "Registrant Organization": r"(?i)(Registrant Organization|Registrant):\s*(.+)",
                "Admin Contact": r"(?i)(Administrative Contact|Admin Contact):\s*(.+)"
            }

            for key, pattern in common_fields.items():
                matches = re.findall(pattern, stdout, re.IGNORECASE | re.MULTILINE)
                if matches:
                    # Flatten list of tuples if regex has OR |
                    flat_matches = []
                    for m_tuple in matches:
                        if isinstance(m_tuple, tuple):
                            flat_matches.extend(filter(None, m_tuple)) # Add non-empty strings from tuple
                        else:
                            flat_matches.append(m_tuple)
                    
                    unique_matches = sorted(list(set(val.strip() for val in flat_matches if val and val.strip())))
                    if unique_matches:
                        parsed[key.replace(" ", "_").lower()] = unique_matches if len(unique_matches) > 1 else unique_matches[0]
            
            results["parsed_data"] = parsed
            if show_live:
                if parsed:
                    self.print_success(f"WHOIS for {target} (parsed):")
                    for k, v in parsed.items(): self.print_info(f"  {k}: {v}")
                else:
                    self.print_warning(f"WHOIS for {target} returned data, but no common fields were parsed. Check raw output.")
        
        if not results["parsed_data"] and not results["errors"] and not stdout: # No output at all
             results["errors"].append(f"WHOIS for {target}: No output received.")
        return results

    def run_traceroute_scan(self) -> Dict[str, Any]:
        target = self._get_option("target")
        timeout_val = int(self._get_option("timeout"))
        show_live = self._get_option("show_live_output") == "true"
        results: Dict[str, Any] = { "command_used": "", "raw_output": "", "hops": [], "errors": [] }

        traceroute_tool_name = "tracert" if sys.platform == "win32" else "traceroute"
        if not self.check_command_exists(traceroute_tool_name):
            results["errors"].append(f"{traceroute_tool_name} tool not found.")
            return results

        cmd = []
        hop_pattern = None
        if sys.platform == "win32":
            cmd = [traceroute_tool_name, "-d", "-w", "1000", target] # -d no DNS, -w 1000ms timeout per hop
             # 1    <1 ms    <1 ms    <1 ms  192.168.1.1
            hop_pattern = re.compile(r"^\s*(\d+)\s+(<?\d+\s*ms|\*)\s+(<?\d+\s*ms|\*)\s+(<?\d+\s*ms|\*)\s+([a-zA-Z0-9\.:\-\_]+(?: \[[^\]]+\])?)")
        else: # Linux/MacOS
            cmd = [traceroute_tool_name, "-n", "-q", "1", "-w", "2", target] # -n no DNS, -q 1 probe, -w 2sec wait
            #  1  192.168.1.1  0.376 ms
            #  With -q 1 it usually shows one time. If multiple probes, then multiple times.
            #  Let's assume standard output for -q 1 for simpler parsing
            hop_pattern = re.compile(r"^\s*(\d+)\s+([a-zA-Z0-9\.:\-\_]+(?:\s*\([^\)]+\))?)\s+([\d\.]+\s*ms|\*)")


        results["command_used"] = " ".join(cmd)
        # Traceroute can take a while, ensure subprocess timeout is generous
        stdout, stderr, returncode = self.run_command(cmd, timeout=timeout_val + 30) # Overall timeout
        results["raw_output"] = stdout

        if "command timed out" in stderr.lower() and returncode == -1:
            results["errors"].append("Traceroute command timed out.")
        elif returncode != 0 and not stdout: # Error and no output to parse
            results["errors"].append(f"Traceroute failed: {stderr.strip() if stderr.strip() else 'Unknown error, RC: '+str(returncode)}")
        else: # Got some output
            for line_num, line in enumerate(stdout.splitlines()):
                if line_num < 1 and "trace complete" not in line.lower(): continue # Skip header lines usually
                match = hop_pattern.match(line.strip())
                if match:
                    groups = match.groups()
                    hop_info = {}
                    if sys.platform == "win32":
                        # hop_num, rtt1, rtt2, rtt3, address_str
                        hop_info = {"hop": int(groups[0]), "rtt1": groups[1].strip(), "rtt2": groups[2].strip(), "rtt3": groups[3].strip(), "address": groups[4].strip()}
                    else: # Linux/macOS with current regex for -q 1
                        # hop_num, address_str, rtt1
                        hop_info = {"hop": int(groups[0]), "address": groups[1].strip(), "rtt1": groups[2].strip()}
                    
                    results["hops"].append(hop_info)
                    if show_live: self.print_success(f"Hop {hop_info['hop']}: {hop_info['address']} ({hop_info.get('rtt1', '*')})")
            
            if not results["hops"] and not results["errors"]: # Output received but no hops parsed
                 if "trace complete" in stdout.lower() or "traceroute to" in stdout.lower() : # headers were there
                    results["errors"].append("Traceroute ran but no hops were successfully parsed. Target might be 1 hop away or unreachable.")
                 else:
                    results["errors"].append("Traceroute output could not be parsed for hops.")


        return results


    def check_command_exists(self, command: str) -> bool:
        """Check if a command exists on the system path."""
        try:
            # Use subprocess.run which is similar to BaseScanner's run_command internals
            # but we only care about existence, not output.
            if sys.platform == "win32":
                # 'where' is a shell command, so shell=True might be needed if it's not directly executable
                # However, 'where' is usually an exe.
                subprocess.run([command, "/?"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2) # Try with a benign arg
            else:
                subprocess.run(["which", command], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False