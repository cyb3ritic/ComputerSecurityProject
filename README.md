# PentestPal
![Readme_Banner](https://github.com/user-attachments/assets/b6a78a61-c7ba-4678-8a6b-9a0a829f5bdc)
*An interactive penetration testing framework for security enthusiasts and professionals.*

PentestPal is a Python-based, command-line penetration testing framework designed to simplify security testing tasks. With a modular architecture, it offers tools for network scanning, vulnerability assessment, and more. Key features like tab-completion, `Ctrl+C` interrupt handling, and detailed reporting make it ideal for both beginners and experienced security professionals.

## Key Features

- **Interactive CLI**: Navigate easily with commands like `use`, `set`, `run`, and `show`.
- **Modular Architecture**: Extend functionality with modules such as `port_scanner`, `xss_scanner`, and more.
- **Port Scanner**: Scan open ports, detect services, and integrate with `nmap` for advanced scans.
- **Tab-Completion**: Autocomplete commands, modules, and options for a seamless experience.
- **Interrupt Handling**: Stop operations gracefully with `Ctrl+C`, displaying a clean result message.
- **Logging**: Track all actions in `pentestpal.log` for auditing and debugging.
- **Cross-Platform**: Compatible with both Linux and Windows.

## Installation

### Prerequisites
- **Python 3.6+**: Ensure Python is installed.
- **pip**: Python package manager for installing dependencies.
- **nmap** (optional): Required for advanced port scanning features in the `port_scanner` module.

### Steps

#### 1. Install Dependencies
Install the required Python packages listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

**requirements.txt**:
```
termcolor>=2.4.0
python-nmap>=0.7.1
```

#### 2. Install PentestPal
Install the package locally:

```bash
pip install .
```

#### 3. Run PentestPal
Start the interactive console:

```bash
pentestpal
```

## Usage

### Starting the Console
Launch PentestPal to access the interactive console:

```bash
pentestpal
```

A welcome banner will display, followed by the `PentestPal>` prompt.

### Available Commands
| Command              | Description                                      |
|----------------------|--------------------------------------------------|
| `use <module>`       | Select a module (e.g., `use port_scanner`).      |
| `set <option> <value>` | Set module options (e.g., `set target 127.0.0.1`). |
| `run`                | Execute the current module.                     |
| `show modules`       | List all available modules.                     |
| `show options`       | Display options for the current module.         |
| `exit`               | Exit the console.                               |
| `help`               | Show the help menu.                             |

### Example: Port Scanning
1. **Select the Port Scanner Module**:
   ```
   use port_scanner
   ```

2. **Set Options**:
   ```
   set target 127.0.0.1
   set ports 1-1000
   set mode quick
   ```

3. **Run the Scan**:
   ```
   run
   ```

4. **Interrupt the Scan (Optional)**:
   - Press `Ctrl+C` to stop the scan.
   - Output: `[x] Result: Scan interrupted by user.` (in red).

5. **View Results**:
   - If the scan completes, it will display open ports, services, and a summary.
   - Example output:
     ```
     [+] Result: Scan completed: 2 open, 998 closed, 0 filtered ports
     ```

### Available Modules
- **`port_scanner`**: Scans for open ports, detects services, and supports `nmap` for advanced scans.
- **`xss_scanner`**: Placeholder for XSS vulnerability scanning (to be implemented).
- **`sqli_scanner`**: Placeholder for SQL injection scanning (to be implemented).
- **`csrf_scanner`**: Placeholder for CSRF vulnerability scanning (to be implemented).
- **`ssrf_scanner`**: Placeholder for SSRF vulnerability scanning (to be implemented).

## Project Structure
```
PentestPal/
├── core/
│   ├── __init__.py
│   ├── logger.py        # Logging setup
│   └── scanner.py       # BaseScanner class for module inheritance
├── modules/
│   ├── __init__.py
│   ├── port_scanner.py  # Port scanning module
│   ├── xss_scanner.py   # XSS scanning module (placeholder)
│   ├── sqli_scanner.py  # SQLi scanning module (placeholder)
│   ├── csrf_scanner.py  # CSRF scanning module (placeholder)
│   └── ssrf_scanner.py  # SSRF scanning module (placeholder)
├── plugins/
│   ├── __init__.py
│   └── banner_generator.py  # Generates the welcome banner
├── main.py              # Entry point for the CLI
├── requirements.txt     # Python dependencies
├── setup.py             # Package setup script
└── README.md            # This file
```

## Contributing
We welcome contributions to PentestPal! To contribute:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/your-feature
   ```
3. Make your changes and commit:
   ```bash
   git commit -m "Add your feature"
   ```
4. Push to your branch:
   ```bash
   git push origin feature/your-feature
   ```
5. Open a pull request on GitHub.

### Adding a New Module
1. Create a new file in the `modules/` directory (e.g., `new_scanner.py`).
2. Define a class that inherits from `BaseScanner` (from `core.scanner`).
3. Implement the `run()` method and define `options_help` for tab-completion.
4. Add the module name to the `module_names` list in `main.py`.

## License
This project is licensed under the MIT License. Below is the full license text:

```
MIT License

Copyright (c) 2025 <Your Name>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contact
For questions, suggestions, or issues, please open an issue on GitHub or contact the maintainer at `<your-email>`.



