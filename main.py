import cmd
import os,sys
import logging
import importlib
import readline
import signal
from core.logger import setup_logger
from termcolor import colored
from plugins import banner_generator

# Configure readline for tab-completion
readline.parse_and_bind("tab: complete")

# Global flag to indicate if an interrupt has occurred
interrupted = False

def signal_handler(sig, frame):
    """Handle SIGINT (Ctrl+C) globally."""
    global interrupted
    interrupted = True
    if not getattr(sys, 'exiting', False):  # Check if Python is exiting
        interrupted = True
        raise KeyboardInterrupt  # Raise KeyboardInterrupt to be caught in the main loop

# Set up signal handler for SIGINT
signal.signal(signal.SIGINT, signal_handler)

class PentestConsole(cmd.Cmd):
    banner_gen = banner_generator.BannerGenerator(module_count=3)
    prompt = colored("PentestPal> ", "blue")
    print(banner_gen.generate_banner())
    
    def __init__(self):
        super().__init__()
        self.current_module = None
        self.options = {}
        self.logger = setup_logger()
        self.logger.info("PentestConsole initialized")
        self.modules = self.load_modules()
        self.commands = ["use", "set", "run", "show", "exit", "help"]

    def load_modules(self):
        """Dynamically load modules from the modules directory."""
        modules = {}
        for file in os.listdir("modules"):
            try:
                if file.endswith(".py") and file != "__init__.py":
                    module_name = file[:-3]  # Remove .py extension
                    module = importlib.import_module(f"modules.{module_name}")
                    class_name = module_name.title().replace("_", "")
                    if hasattr(module, class_name):
                        modules[module_name] = getattr(module, class_name)
                    else:
                        print(colored(f"[-] Module '{module_name}' does not have a class named '{class_name}'.", "red"))
            except ImportError as e:
                print(colored(f"[-] Failed to import module '{module_name}': {e}", "red"))
                continue        
        if not modules:
            print(colored("[-] No modules loaded.", "red"))
        else:
            print(colored(f"[+] Loaded {len(modules)} modules.", "green"))

        return modules
    

    def complete(self, text, state):
        """Custom completion function for readline."""
        if state == 0:  # First time for this text, build match list
            line = readline.get_line_buffer().lstrip().lower()  # Case-insensitive matching
            if not line or line.isspace():
                self.matches = [c for c in self.commands + list(self.modules.keys()) if c.startswith(text)]
            elif line.startswith("use "):
                module_text = text if len(line.split()) > 1 else ""
                self.matches = [m for m in self.modules.keys() if m.startswith(module_text)]
            elif line.startswith("show "):
                show_options = ["modules", "options"]
                show_text = text if len(line.split()) > 1 else ""
                self.matches = [o for o in show_options if o.startswith(show_text)]
            elif line.startswith("set") and self.current_module:  # Check for "set" prefix (with or without space)
                # Split the line to get the current word being typed
                parts = line.split()
                if len(parts) == 1:  # User typed "set" or "set "
                    option_text = text.lower() if text else ""
                    # Suggest option names
                    if hasattr(self.current_module, "options_help") and isinstance(self.current_module.options_help, dict):
                        self.matches = [o for o in self.current_module.options_help.keys() if o.lower().startswith(option_text)]
                    else:
                        self.matches = []
                elif len(parts) == 2:  # User typed "set <option>" (e.g., "set mode")
                    option_text = parts[1].lower()
                    # Suggest option names
                    if hasattr(self.current_module, "options_help") and isinstance(self.current_module.options_help, dict):
                        self.matches = [o for o in self.current_module.options_help.keys() if o.lower().startswith(option_text)]
                    else:
                        self.matches = []
                elif len(parts) >= 3:  # User typed "set <option> " (e.g., "set mode q")
                    option = parts[1].lower()
                    value_text = parts[2].lower() if len(parts) > 2 else text.lower()
                    # Suggest option values
                    if hasattr(self.current_module, "options_help") and isinstance(self.current_module.options_help, dict):
                        if option in self.current_module.options_help:
                            desc, valid_values = self.current_module.options_help[option]
                            if valid_values:  # If there are predefined values, suggest them
                                self.matches = [v for v in valid_values if v.lower().startswith(value_text)]
                            else:
                                self.matches = []  # No predefined values, no suggestions
                        else:
                            self.matches = []
                    else:
                        self.matches = []
                else:
                    self.matches = []
            else:
                self.matches = [c for c in self.commands if c.startswith(text)]
        try:
            return self.matches[state]
        except IndexError:
            return None

    def do_use(self, module_name):
        """Select a module to use."""
        if module_name in self.modules:
            self.current_module = self.modules[module_name]()
            print(colored(f"[+] Module set to: {module_name}", "green"))
            self.prompt = colored(f"PentestPal | {module_name}> ", "blue")
        else:
            print(colored(f"[-] Module '{module_name}' not found.", "red"))
        

    def do_set(self, arg):
        """Set an option for the current module."""
        if not self.current_module:
            print(colored("[-] No module selected. Use 'use <module>' first.", "red"))
            return
        args = arg.split()
        if len(args) != 2:
            print(colored("[-] Usage: set <option> <value>", "red"))
            return
        option, value = args
        self.options[option] = value
        print(colored(f"[+] {option} => {value}", "green"))

    def do_run(self, arg):
        """Run the current module."""
        global interrupted
        if not self.current_module:
            print(colored("[-] No module selected. Use 'use <module>' first.", "red"))
            return
        try:
            self.current_module.options = self.options
            result = self.current_module.run()
            # Print in red if interrupted, green otherwise
            color = "red" if result == "Scan interrupted by user." else "green"
            symbol = "x" if result == "Scan interrupted by user." else "+"
            print(colored(f"[{symbol}] Result: {result}", color))
            self.logger.info(f"Module {self.current_module.__class__.__name__} completed with result: {result}")
        except KeyboardInterrupt:
            interrupted = False  # Reset the flag
        except Exception as e:
            print(colored(f"[-] Error running module: {e}", "red"))
            self.logger.info(f"Module {self.current_module.__class__.__name__} failed with error: {e}")

    def do_show(self, arg):
        """Show available modules or options for the current module."""
        if arg.lower() == "modules":
            self.show_modules()
        elif arg.lower() == "options":
            self.show_options()
        else:
            print(colored("[-] Usage: show <modules|options>", "red"))

    def show_modules(self):
        """Display all available modules."""
        print(colored("[+] Available Modules:", "green"))
        if self.modules:
            for module_name in self.modules:
                print(colored(f"  - {module_name}", "yellow"))
        else:
            print(colored("  - No modules loaded.", "yellow"))

    def show_options(self):
        """Display available options for the current module."""
        if not self.current_module:
            print(colored("[-] No module selected. Use 'use <module>' first.", "red"))
            return

        print(colored(f"[+] Available Options for {self.current_module.__class__.__name__}:", "green"))
        if hasattr(self.current_module, "options_help"):
            for option, description in self.current_module.options_help.items():
                print(colored(f"  - {option}: {description}", "yellow"))
        else:
            print(colored("  - No specific options defined for this module.", "yellow"))


    def do_exit(self, arg):
        """Exit the console.
        
        Usage: exit [--force]
        Options:
            --force  Skip cleanup and exit immediately
        """
        sys.exiting = True
        try:
            if not getattr(self, '_exiting', False):  # Prevent re-entrancy
                self._exiting = True
                self.logger.info("~~~~~~~~~~ SESSION ENDED ~~~~~~~~~~\n")
                
                # Handle --force flag
                if arg == "--force":
                    print(colored("[!] Force exiting...", "yellow"))
                    os._exit(0)
                
                # Normal exit procedure
                print(colored("[+] Exiting...", "green"))
                
                # Add any cleanup operations here
                if hasattr(self, 'cleanup'):
                    self.cleanup()
                
                # Ensure all logs are flushed
                for handler in self.logger.handlers:
                    handler.flush()
                    if isinstance(handler, logging.FileHandler):
                        handler.close()
                return True              
        except Exception as e:
            print(colored(f"[!] Exit failed: {e}", "red"))
            print(colored(f"[!] Try exit --force", "yellow"))
            self._exiting = False
            return False


    def do_help(self, arg):
        """Show help menu."""
        print(colored("""
Available Commands:
  use <module>      - Select a module (e.g., port_scanner)
  set <option> <value> - Set an option for the current module
  run               - Run the current module
  show modules      - Show available modules
  show options      - Show available options for the current module
  exit              - Exit the console
  help              - Show this help menu
        """, "yellow"))

    def precmd(self, line):
        """Log every command before execution."""
        self.logger.info(f"Command: {line}")
        return line

    def custom_cmdloop(self, intro=None):
        """Custom command loop with readline completion."""
        if intro:
            print(intro)
        while True:
            try:
                line = input(self.prompt).strip()
                if not line:
                    continue
                line = self.precmd(line)
                if self.onecmd(line):
                    break
            except KeyboardInterrupt:
                print(colored("^C", "red"))
                global interrupted
                interrupted = False
            except EOFError:
                print()
                break
            except Exception as e:
                print(colored(f"[-] Error: {e}", "red"))



def main():
    console = PentestConsole()
    readline.set_completer(console.complete)
    console.custom_cmdloop(colored("[+] Welcome to the PentestPal!", "green"))

if __name__ == "__main__":
    main()