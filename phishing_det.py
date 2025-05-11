import requests
import time
import base64


API_KEY = "3abb9cb2f0be365345b06f327d2054bf4c3411209740adc1cb3904b1aaebf3a7"

# VirusTotal endpoints
SCAN_URL = "https://www.virustotal.com/api/v3/urls"
RESULT_URL = "https://www.virustotal.com/api/v3/analyses/"

def encode_url(url: str) -> str:
    """Encode URL into base64 format required by VirusTotal"""
    url_bytes = url.encode('utf-8')
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    return base64_bytes.decode('utf-8').strip('=')

def submit_url_to_virustotal(url: str) -> str | None:
    """Send the URL to VirusTotal for analysis"""
    headers = {"x-apikey": API_KEY}
    data = {"url": url}

    response = requests.post(SCAN_URL, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()['data']['id']
    else:
        print(f"[!] Submission error: {response.status_code} - {response.text}")
        return None

def fetch_analysis_report(analysis_id: str) -> dict | None:
    """Fetch the analysis results using the analysis ID"""
    headers = {"x-apikey": API_KEY}
    response = requests.get(RESULT_URL + analysis_id, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"[!] Failed to retrieve report: {response.status_code} - {response.text}")
        return None

def display_results(report: dict) -> None:
    """Display the scan results in a readable format"""
    stats = report['data']['attributes']['stats']
    harmless = stats.get("harmless", 0)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)

    total = harmless + malicious + suspicious + undetected
    threat_score = ((malicious + suspicious) / total) * 100 if total > 0 else 0

    print("\n[+] Scan Results:")
    print(f"    Harmless:     {harmless}")
    print(f"    Suspicious:   {suspicious}")
    print(f"    Malicious:    {malicious}")
    print(f"    Undetected:   {undetected}")
    print(f"\n    Threat Score: {threat_score:.2f}%")

    if threat_score > 50:
        print("    ⚠️  Warning: This URL might be malicious or phishing.")
    else:
        print("    ✅ Safe: No major threats detected.")

def analyze_url(url: str) -> None:
    """Main function to handle analysis workflow"""
    print(f"\n[*] Submitting URL for analysis: {url}")
    analysis_id = submit_url_to_virustotal(url)
    if not analysis_id:
        return

    print("[*] Waiting for the report...")
    time.sleep(15)

    report = fetch_analysis_report(analysis_id)
    if report:
        display_results(report)

if __name__ == "__main__":
    print("🔍 Phishing URL Scanner ")
    user_url = input("Enter the URL to scan: ").strip()
    
    if user_url:
        analyze_url(user_url)
    else:
        print("[!] No URL entered. Exiting.")

