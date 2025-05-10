import os
import sys
import time
import re
import json
import ipaddress
import datetime
from typing import Dict, List, Tuple, Optional, Any, Union
from core.scanner import BaseScanner
from termcolor import colored

class PortScanner(BaseScanner):
    """Nmap-based port scanner module"""
    
    def __init__(self):
        super().__init__()
        
        # Define default options
        self.options = {
            "target": "",
            "scan_type": "quick",
            "ports": "default",
            "timeout": "300",
            "output_file": "",
            "output_format": "all",
            "custom_flags": "",
            "show_live_output": "false",
        }
        
        # Define scan types with their nmap flags
        self.scan_types = {
            "quick": "-F",                          # Fast scan (top 100 ports)
            "default": "-sV",                        # Service version detection
            "service": "-sV -sC",                    # Service scan with default scripts
            "comprehensive": "-sV -sC -O",           # Service scan with OS detection
            "aggressive": "-A -T4",                  # Aggressive scan
            "stealth": "-sS -T2",                    # Stealth scan
            "udp": "-sU --top-ports 100",            # UDP scan of top 100 ports
            "all_ports": "-p-",                      # All 65535 ports
            "vuln": "-sV --script=vuln",             # Vulnerability scan
            "safe_scripts": "-sV --script=safe",     # Safe scripts scan
            "web": "-p 80,443,8080,8443 --script=http-*", # Web scan
            "custom": ""                             # Custom scan (requires custom_flags)
        }
        
        # Help text for options
        self.options_help = {
            "target": ("Target IP, hostname, or CIDR range to scan", []),
            "scan_type": ("Type of scan to perform", list(self.scan_types.keys())),
            "ports": ("Port(s) to scan (comma-separated, range, or 'default')", []),
            "timeout": ("Scan timeout in seconds", ["60", "120", "300", "600"]),
            "output_file": ("Base filename to save the scan results (without extension)", []),
            "output_format": ("Output format(s)", ["all", "json", "xml", "nmap", "none"]),
            "custom_flags": ("Custom nmap flags (used with scan_type=custom)", []),
            "show_live_output": ("Show live output during scan", ["true", "false"]),
        }
        
        # Define required options
        self.required_options = ["target"]
        
        # Define required commands
        self.required_commands = ["nmap"]
        
        # Set up the result storage
        self.scan_results = {
            "start_time": "",
            "end_time": "",
            "target": "",
            "command": "",
            "scan_type": "",
            "hosts_up": 0,
            "hosts_down": 0,
            "open_ports": [],
        }
    
    def validate_options(self) -> Tuple[bool, str]:
        """Validate the options for this scanner"""
        # Check required commands
        valid_commands, error_message = self.validate_required_commands(self.required_commands)
        if not valid_commands:
            return False, error_message
        
        # Check required options
        for option in self.required_options:
            if not self.options.get(option):
                return False, f"Missing required option: {option}"
        
        # Validate target format
        target = self.options.get("target", "")
        if not target:
            return False, "Target is required"
            
        # Basic validation for IP, CIDR, or hostname
        # (This is basic - nmap will do more thorough validation)
        
        # Validate scan type
        scan_type = self.options.get("scan_type", "quick")
        if scan_type not in self.scan_types:
            return False, f"Invalid scan type: {scan_type}. Available types: {', '.join(self.scan_types.keys())}"
        
        # If scan_type is custom, validate custom_flags
        if scan_type == "custom" and not self.options.get("custom_flags"):
            return False, "Custom flags are required when scan_type is set to 'custom'"
        
        # Validate ports format
        ports = self.options.get("ports", "default")
        if ports != "default":
            # Check if ports is a valid nmap port specification
            # Allow comma-separated values and ranges
            port_parts = ports.split(',')
            for part in port_parts:
                part = part.strip()
                # Check if it's a range (e.g., 80-100)
                if '-' in part:
                    start, end = part.split('-')
                    try:
                        start_port = int(start.strip())
                        end_port = int(end.strip())
                        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                            return False, f"Invalid port range: {part}. Ports must be between 1-65535"
                    except ValueError:
                        return False, f"Invalid port range: {part}"
                else:
                    # Single port
                    try:
                        port_num = int(part)
                        if not (1 <= port_num <= 65535):
                            return False, f"Invalid port: {part}. Ports must be between 1-65535"
                    except ValueError:
                        return False, f"Invalid port: {part}"
        
        # Validate timeout
        try:
            timeout = int(self.options.get("timeout", 300))
            if timeout <= 0:
                return False, "Timeout must be a positive integer"
        except ValueError:
            return False, "Timeout must be a positive integer"
        
        # Validate output format
        output_format = self.options.get("output_format", "all")
        valid_formats = ["all", "json", "xml", "nmap", "none"]
        if output_format not in valid_formats:
            return False, f"Invalid output format: {output_format}. Valid formats: {', '.join(valid_formats)}"
        
        # Validate show_live_output
        show_live_output = self.options.get("show_live_output", "false").lower()
        if show_live_output not in ["true", "false"]:
            return False, "show_live_output must be 'true' or 'false'"
        
        return True, ""
    
    def build_command(self) -> List[str]:
        """Build the nmap command based on current options"""
        target = self.options.get("target", "")
        scan_type = self.options.get("scan_type", "quick")
        ports = self.options.get("ports", "default")
        output_file = self.options.get("output_file", "")
        output_format = self.options.get("output_format", "all")
        custom_flags = self.options.get("custom_flags", "")
        
        # Start with base command
        command = ["nmap"]
        
        # Add scan type flags
        if scan_type == "custom":
            # Parse custom flags string into list
            custom_flags_list = []
            if custom_flags:
                try:
                    # Use shlex to properly handle quoted strings
                    import shlex
                    custom_flags_list = shlex.split(custom_flags)
                except Exception as e:
                    self.logger.error(f"Error parsing custom flags: {e}")
                    custom_flags_list = custom_flags.split()
            command.extend(custom_flags_list)
        else:
            # Add predefined scan flags
            command.extend(self.scan_types[scan_type].split())
        
        # Add port specification if provided
        if ports != "default":
            command.extend(["-p", ports])
        
        # Add output options if output file is specified and format isn't 'none'
        if output_file and output_format != "none":
            if output_format == "all" or output_format == "xml":
                xml_output = f"{output_file}.xml"
                command.extend(["-oX", xml_output])
            
            if output_format == "all" or output_format == "nmap":
                nmap_output = f"{output_file}.nmap"
                command.extend(["-oN", nmap_output])
        
        # Add target
        command.append(target)
        
        return command
    


    def run(self) -> str:
        """Run the port scanner with the current options"""
        # Validate options
        valid, error_message = self.validate_options()
        if not valid:
            return f"Validation error: {error_message}"
        
        try:
            # Build command
            command = self.build_command()
            
            # Store command for results
            self.scan_results["command"] = command
            self.scan_results["target"] = self.options.get("target")
            self.scan_results["scan_type"] = self.options.get("scan_type")
            
            # Determine if we should show live output
            show_live_output = self.options.get("show_live_output", "false").lower() == "true"
            
            # Log the start time
            start_time = datetime.datetime.now()
            self.scan_results["start_time"] = start_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Execute the command
            timeout = int(self.options.get("timeout", 300))
            self.logger.info(f"Starting scan with timeout {timeout}s")
            print(colored(f"[*] Running nmap scan against {self.options.get('target')}...", "yellow"))
            print(colored(f"[*] Command: {' '.join(command)}", "yellow"))
            print(colored(f"[*] This may take a while depending on the scan type and target...", "yellow"))
            
            return_code, stdout, stderr = self.execute_command(command, timeout, show_live_output)
            
            # Log the end time
            end_time = datetime.datetime.now()
            self.scan_results["end_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Calculate duration
            duration = end_time - start_time
            duration_str = str(duration).split('.')[0]  # Remove microseconds
            self.scan_results["duration"] = duration_str
            
            # Check if the scan was interrupted
            if self.interrupted:
                return "Scan interrupted by user."
            
            # Check for errors
            if return_code != 0:
                self.logger.error(f"Scan failed with return code {return_code}")
                self.logger.error(f"Error: {stderr}")
                return f"Scan failed: {stderr}"
            
            # Parse and format results
            results = self.parse_nmap_output(stdout)
            
            # Save results to file if requested
            self.save_results(results)
            
            # Update the scan results
            self.scan_results.update(results)
            
            # Format and return results
            return self.format_results(results)
            
        except KeyboardInterrupt:
            self.interrupted = True
            return "Scan interrupted by user."
            
        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            return f"Error during scan: {str(e)}"