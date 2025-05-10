import json
import subprocess
from typing import Dict, List, Optional, Tuple
from termcolor import colored

class BaseScanner:
    """Base class for all scanner modules"""
    
    def __init__(self):
        self.options = {}
        self.required_options = []
        self.scan_results = {}
        self.scan_types = {}
    
    def validate_options(self) -> Tuple[bool, str]:
        """Validate scanner options"""
        for option in self.required_options:
            if not self.options.get(option):
                return False, f"Missing required option: {option}"
        return True, "Options validated"
    
    def run(self) -> Dict:
        """Run the scan - to be implemented by child classes"""
        raise NotImplementedError("Subclasses must implement run_scan()")
    
    def save_results(self, filename: str) -> bool:
        """Save scan results to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            return True
        except Exception as e:
            self.print_error(f"Failed to save results: {str(e)}")
            return False
    
    def print_info(self, message: str) -> None:
        """Print informational message"""
        print(colored("[*] ", "blue") + message)
    
    def print_success(self, message: str) -> None:
        """Print success message"""
        print(colored("[+] ", "green") + message)
    
    def print_warning(self, message: str) -> None:
        """Print warning message"""
        print(colored("[!] ", "yellow") + message)
    
    def print_error(self, message: str) -> None:
        """Print error message"""
        print(colored("[-] ", "red") + message)
    
    def run_command(self, command: List[str], timeout: int = 60) -> Tuple[str, str, int]:
        """Run a system command with timeout"""
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except Exception as e:
            return "", str(e), -1