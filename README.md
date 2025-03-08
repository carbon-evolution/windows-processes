# Windows Process Analyzer

A powerful Python utility for monitoring, analyzing, and detecting suspicious Windows processes. This tool helps identify potentially problematic processes based on resource usage, location, and behavior patterns.

## Features

- 📊 Displays detailed information about all running processes
- 🚨 Flags high resource usage processes (CPU >80% or memory >1GB)
- ⚠️ Identifies suspicious processes based on executable location and behavior
- 📈 Provides a summary of system process health
- 🔍 Checks for potential vulnerabilities like suspicious ports and system privileges

## Requirements

- Windows operating system
- Python 3.6+
- Administrator privileges (for complete access to all process information)

## Installation

1. Clone this repository or download the source code
2. Install the required dependencies:

```
pip install -r requirements.txt
```

## Usage

Run the script with administrator privileges for best results:

```
python check_suspicious_processes.py
```

### Understanding the Output

The script categorizes processes into three status levels:

- 🔴 **HIGH USAGE**: Processes consuming significant system resources
- ⚠️ **SUSPICIOUS**: Processes that might require further investigation
- ✅ **NORMAL**: Processes operating within normal parameters

## Why Use This Tool?

- **Security Monitoring**: Identify potentially malicious processes
- **System Performance**: Find resource-hungry applications affecting system performance
- **Troubleshooting**: Diagnose system issues by examining process behavior
- **IT Administration**: Monitor system health and detect anomalies

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 