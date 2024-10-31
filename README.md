markdown
# WebBuster

This Python script performs a comprehensive vulnerability scan on a specified website using multiple APIs, including OWASP ZAP, Shodan, VirusTotal, and SSL Labs. The script also includes checks for missing security headers, subdomain enumeration, port scanning, and CVE-based exploit lookups. It generates a consolidated report of the findings in JSON format.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [APIs Used](#apis-used)
- [Output](#output)
- [Error Handling](#error-handling)


## Requirements

- **Python 3.7+**
- External dependencies:
  - `requests`: For making HTTP requests to various APIs.
  
  Install with:
  ```bash
  pip install requests
  ```

- **API Keys**:
  To use this script, you will need to sign up for API keys from the following services:
  - **OWASP ZAP**: For launching web application vulnerability scans.
  - **Shodan**: For retrieving public vulnerability data about the IP or domain.
  - **VirusTotal**: For analyzing URLs for malware or phishing.
  - **SSL Labs**: For checking SSL/TLS configurations.

  Place these keys in the `API_KEYS` dictionary in the script, replacing `"your_owasp_zap_api_key"`, `"your_shodan_api_key"`, `"your_virustotal_api_key"`, and `"your_ssl_labs_api_key"` with your actual keys.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/TFourie30/WebBuster.git
   cd WebBuster
   ```

2. Install required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the script, specify the target URL in the `TARGET_URL` variable at the top of the script. Then execute:

```bash
python WebBuster.py
```

### Example

Set the target URL:

```python
TARGET_URL = 'http://example.com'
```

Run the scan:

```bash
python WebBuster.py
```

The results will be saved in a JSON report file, `ultimate_vulnerability_report.json`, in the project directory.

## APIs Used

The script uses the following APIs to perform a comprehensive vulnerability scan:

1. **OWASP ZAP**: Launches an active scan on the target URL to detect vulnerabilities within the web application.
2. **Shodan**: Retrieves public data about the server hosting the domain, including open ports, services, and known vulnerabilities.
3. **VirusTotal**: Checks for any known threats associated with the URL, identifying potential malware or phishing attempts.
4. **SSL Labs**: Analyzes SSL/TLS configurations for potential weaknesses.

The script also performs:
- **Header Analysis**: Checks if essential security headers are present in the HTTP response.
- **Subdomain Enumeration**: Returns mock subdomains for demonstration (can be replaced with a real subdomain enumeration tool).
- **Port Scanning**: A basic mock port scan; replace with a real scanning tool or API if needed.
- **Exploit Database Lookup**: Searches for exploits based on CVE IDs (simulated; replace with a real database query if required).

## Output

The script generates a consolidated JSON report (`ultimate_vulnerability_report.json`) with the following structure:

```json
{
    "ZAP Scan": [ ... ],
    "Shodan Scan": { ... },
    "VirusTotal Analysis": { ... },
    "SSL Labs Analysis": { ... },
    "Header Analysis": { ... },
    "Subdomain Enumeration": [ ... ],
    "Port Scan": [ ... ],
    "Exploits": { ... }
}
```

Each section provides details on the vulnerabilities or configurations identified by each tool.

## Error Handling

The script includes error handling to ensure it runs smoothly even if one of the services or APIs is unavailable. Common exceptions, such as network timeouts or API errors, are handled, and an error message will be printed for each issue. If an unexpected issue arises, the script will log the problem and continue with the remaining scans.


