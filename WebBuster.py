import requests
import json
import time
import base64
from urllib.parse import urlparse

# Configuration for API Keys
API_KEYS = {
    "zap": "your_owasp_zap_api_key",
    "shodan": "your_shodan_api_key",
    "virustotal": "your_virustotal_api_key",
    "ssl_labs": "your_ssl_labs_api_key",
}

TARGET_URL = 'http://example.com'
ZAP_API_BASE = 'http://localhost:8080'

def zap_scan(target_url):
    """Initiates a scan on the target website using OWASP ZAP API."""
    try:
        zap_scan_url = ZAP_API_BASE + '/JSON/ascan/action/scan/'
        zap_alerts_url = ZAP_API_BASE + '/JSON/core/view/alerts/'
        params = {'apikey': API_KEYS['zap'], 'url': target_url, 'recurse': True, 'method': 'GET'}

        response = requests.get(zap_scan_url, params=params, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses

        scan_id = response.json().get('scan')
        if not scan_id:
            print("Failed to start ZAP scan: No scan ID returned.")
            return []

        status_url = ZAP_API_BASE + '/JSON/ascan/view/status/'
        while True:
            try:
                status_response = requests.get(status_url, params={'scanId': scan_id}, timeout=5)
                status = status_response.json().get('status')
                if status == '100':  # 100% indicates scan completion
                    print("ZAP scan completed.")
                    break
                time.sleep(5)
            except requests.RequestException as e:
                print(f"Error checking ZAP scan status: {e}")
                break

        alert_response = requests.get(zap_alerts_url, params={'apikey': API_KEYS['zap'], 'baseurl': target_url}, timeout=10)
        alert_response.raise_for_status()
        return alert_response.json().get('alerts', [])
    except requests.RequestException as e:
        print(f"Error in ZAP scan: {e}")
    return []

def shodan_scan(target_url):
    """Uses Shodan API to retrieve info about IP or domain vulnerabilities."""
    try:
        domain = urlparse(target_url).netloc
        shodan_url = f'https://api.shodan.io/shodan/host/{domain}?key={API_KEYS["shodan"]}'
        response = requests.get(shodan_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error in Shodan scan: {e}")
    return {}

def virustotal_scan(target_url):
    """Uses VirusTotal API to analyze the URL for malicious flags."""
    try:
        vt_url = f'https://www.virustotal.com/api/v3/urls'
        headers = {"x-apikey": API_KEYS["virustotal"]}
        vt_encoded_url = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        response = requests.get(f"{vt_url}/{vt_encoded_url}", headers=headers, timeout=10)
        response.raise_for_status()
        return response.json().get('data', {}).get('attributes', {})
    except requests.RequestException as e:
        print(f"Error in VirusTotal scan: {e}")
    return {}

def ssl_labs_scan(target_url):
    """Uses SSL Labs API to analyze SSL/TLS config of the target domain."""
    try:
        domain = urlparse(target_url).netloc
        ssl_url = f'https://api.ssllabs.com/api/v3/analyze?host={domain}'
        response = requests.get(ssl_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error in SSL Labs scan: {e}")
    return {}

def header_analysis(target_url):
    """Analyzes HTTP headers for missing security configurations."""
    try:
        response = requests.get(target_url, timeout=10)
        headers_info = {}
        headers = response.headers

        security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
                            "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"]
        for header in security_headers:
            headers_info[header] = headers.get(header, "Missing")
        return headers_info
    except requests.RequestException as e:
        print(f"Error in header analysis: {e}")
    return {}

def subdomain_enumeration(domain):
    """Mock subdomain enumeration; replace with real API or tool as needed."""
    try:
        return ["sub1." + domain, "sub2." + domain]
    except Exception as e:
        print(f"Error in subdomain enumeration: {e}")
    return []

def port_scan(domain):
    """Mock port scanning; replace with real tool or API for actual results."""
    try:
        return [{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]
    except Exception as e:
        print(f"Error in port scan: {e}")
    return []

def exploit_db_search(cve_list):
    """Mock search for exploits based on CVEs."""
    try:
        exploits = {}
        for cve in cve_list:
            exploits[cve] = f"Exploit found for {cve} at https://exploit-db.com/{cve}"
        return exploits
    except Exception as e:
        print(f"Error in exploit search: {e}")
    return {}

def generate_report(zap_data, shodan_data, virustotal_data, ssl_data, headers_data, subdomains, ports, exploits):
    """Consolidates all findings into a structured report."""
    report = {
        "ZAP Scan": zap_data,
        "Shodan Scan": shodan_data,
        "VirusTotal Analysis": virustotal_data,
        "SSL Labs Analysis": ssl_data,
        "Header Analysis": headers_data,
        "Subdomain Enumeration": subdomains,
        "Port Scan": ports,
        "Exploits": exploits,
    }
    return report

def save_report(report_data, file_name='WebBuster_vulnerability_report.json'):
    """Saves the final report data to a JSON file."""
    try:
        with open(file_name, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f'Report saved as {file_name}')
    except IOError as e:
        print(f"Error saving report: {e}")

def main():
    domain = urlparse(TARGET_URL).netloc

    try:
        zap_data = zap_scan(TARGET_URL)
        shodan_data = shodan_scan(TARGET_URL)
        virustotal_data = virustotal_scan(TARGET_URL)
        ssl_data = ssl_labs_scan(TARGET_URL)
        headers_data = header_analysis(TARGET_URL)
        subdomains = subdomain_enumeration(domain)
        ports = port_scan(domain)

        cves_found = ["CVE-2022-1234", "CVE-2023-5678"]
        exploits = exploit_db_search(cves_found)

        report_data = generate_report(zap_data, shodan_data, virustotal_data, ssl_data, headers_data, subdomains, ports, exploits)
        
        save_report(report_data)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
