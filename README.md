# WebBuster

WebBuster is a comprehensive website vulnerability scanner written in Python. This tool performs various vulnerability checks on target websites, including port scanning, SQL injection, server details extraction, and more. Designed for security researchers and developers, WebBuster consolidates multiple security scans into one streamlined program for quick and reliable results.

## Features

WebBuster comes with a range of features, covering popular web security checks:

1. **Vulnerability Scanning with APIs**: Uses multiple vulnerability databases to detect known vulnerabilities associated with website technologies.
2. **SQL Injection Detection**: Attempts to identify SQL injection vulnerabilities on exposed URLs.
3. **Server Information and OS Detection**: Extracts server and operating system details to determine potential vulnerabilities based on server configuration.
4. **Port Scanning**: Scans the top 1000 most common ports to detect open services that may indicate exposed or misconfigured applications.
5. **WHOIS Lookup**: Retrieves WHOIS data to give insights into domain ownership and registration details.
6. **Extensible and Crash-Resistant**: Built to handle network interruptions and unexpected errors gracefully, providing a stable scan process even in unstable environments.

## Installation

To use WebBuster, you need Python 3.x and a few required libraries. Clone this repository and install the necessary dependencies:

```bash
git clone https://github.com/yourusername/WebBuster.git
cd WebBuster
pip install -r requirements.txt
```

## Usage

WebBuster is customizable and easy to use. Simply provide a target URL, and WebBuster will perform a comprehensive scan of the target website.

### Basic Usage

To run a scan on a target website:

```bash
python WebBuster.py --url <target_url>
```

Replace `<target_url>` with the actual URL of the site you want to scan. The tool will initiate a full scan covering all enabled functionalities.

### Optional Arguments

WebBuster allows you to customize its operations via optional arguments:

- `--url <target_url>`: (Required) Specifies the URL to scan.
- `--output <output_file>`: (Optional) Exports results to a specified file in `.txt` or `.json` format.
- `--timeout <seconds>`: (Optional) Sets the timeout for network requests (default: 5 seconds).
- `--verbose`: (Optional) Prints detailed output for each scan, including individual port scans and vulnerability details.

### Example Usage

```bash
python WebBuster.py --url https://example.com --output results.json --verbose
```

## Detailed Functionalities

1. **API-based Vulnerability Scanning**: WebBuster integrates multiple vulnerability databases to check the target website for known security vulnerabilities. By cross-referencing technologies and software versions against these databases, WebBuster provides a comprehensive report on potential weaknesses.

2. **SQL Injection Testing**: WebBuster tests the URLs of target websites for SQL injection vulnerabilities. This feature is especially useful for dynamic websites with form fields, as it evaluates potential injection points and alerts users to any potential risk.

3. **Server Information and OS Version Detection**: WebBuster extracts details about the server, such as the operating system and version, to evaluate possible exploits associated with specific configurations.

4. **Top 1000 Ports Scan**: A thorough port scan on the target URL, checking the 1000 most commonly used ports, reveals any open services that might be exploited. Each open port is flagged and checked for potential issues.

5. **WHOIS Lookup**: WebBuster performs a WHOIS lookup on the target domain, displaying ownership, registration dates, and other relevant information to help with security profiling.

## Output

WebBuster produces detailed results for each scan in the terminal, but you can also export the output to a `.json` or `.txt` file for further analysis.

### Example Output

```json
{
  "url": "https://example.com",
  "open_ports": [80, 443, 8080],
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "severity": "High",
      "description": "Potential SQL Injection vulnerability found on /login endpoint"
    }
  ],
  "server_info": {
    "os": "Linux",
    "server": "Apache/2.4.41"
  },
  "whois": {
    "domain": "example.com",
    "registrant": "John Doe",
    "creation_date": "2003-06-15",
    "expiry_date": "2025-06-15"
  }
}
```

## Disclaimer

WebBuster is intended for educational and testing purposes only. It is the responsibility of the user to obtain permission before scanning any website that they do not own or have explicit permission to test. Misuse of WebBuster may lead to legal consequences.

## Contributing

Contributions to WebBuster are welcome! If you would like to add more functionalities or improve the code, feel free to submit a pull request.

## Author
This script is maintained by Tobias Fourie.
```
