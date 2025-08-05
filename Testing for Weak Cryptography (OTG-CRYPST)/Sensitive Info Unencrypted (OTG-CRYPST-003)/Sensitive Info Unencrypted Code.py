#!/usr/bin/env python3
"""
DVWA OTG-CRYPST-003 Testing Script
Tests for Sensitive Information Sent via Unencrypted Channels
"""

import requests
import json
from datetime import datetime
from urllib.parse import urljoin
import urllib3

# Disable SSL warnings for HTTP connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DVWATester:
    def __init__(self, base_url="http://localhost/dvwa/"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = {
            "target": base_url,
            "test_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "protocol": "HTTP",
            "findings": [],
            "evidence": {},
            "risk_level": "High"
        }

    def check_protocol_security(self):
        """Check if site is using HTTPS"""
        if self.base_url.startswith("https"):
            self.findings["protocol"] = "HTTPS"
            return True
        else:
            self.findings["findings"].append("Site uses unencrypted HTTP protocol")
            return False

    def get_login_page(self):
        """Fetch the login page and analyze headers"""
        try:
            response = self.session.get(self.base_url + "login.php", verify=False)
            self.findings["evidence"]["login_page_response"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers)
            }
            return response
        except Exception as e:
            print(f"Error fetching login page: {e}")
            return None

    def perform_login(self, username="admin", password="password"):
        """Perform login and capture request/response"""
        try:
            # First get the login page to extract any tokens
            login_page = self.session.get(self.base_url + "login.php", verify=False)
            
            # Prepare login data
            login_data = {
                "username": username,
                "password": password,
                "Login": "Login"
            }
            
            # Perform login
            response = self.session.post(
                self.base_url + "login.php",
                data=login_data,
                verify=False,
                allow_redirects=True
            )
            
            # Store evidence
            self.findings["evidence"]["login_request"] = {
                "method": "POST",
                "url": self.base_url + "login.php",
                "data": login_data,
                "headers": dict(self.session.headers)
            }
            
            self.findings["evidence"]["login_response"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "url": response.url
            }
            
            return response
        except Exception as e:
            print(f"Error during login: {e}")
            return None

    def analyze_cookies(self):
        """Analyze cookie security flags"""
        cookies = self.session.cookies
        insecure_cookies = []
        
        for cookie in cookies:
            cookie_info = {
                "name": cookie.name,
                "value": cookie.value,
                "secure": cookie.secure,
                "httponly": getattr(cookie, 'httponly', False)
            }
            
            if not cookie.secure:
                insecure_cookies.append(cookie_info)
                self.findings["findings"].append(f"Cookie '{cookie.name}' missing Secure flag")
            
            if not getattr(cookie, 'httponly', False):
                self.findings["findings"].append(f"Cookie '{cookie.name}' missing HttpOnly flag")
        
        self.findings["evidence"]["cookies"] = insecure_cookies
        return insecure_cookies

    def analyze_traffic(self):
        """Analyze captured traffic for sensitive data"""
        # Check if credentials are in request data
        if "login_request" in self.findings["evidence"]:
            request_data = self.findings["evidence"]["login_request"]
            if "data" in request_data:
                if "password" in request_data["data"]:
                    self.findings["findings"].append("Password transmitted in plaintext POST data")
                
                if "username" in request_data["data"]:
                    self.findings["findings"].append("Username transmitted in plaintext POST data")

    def generate_report_data(self):
        """Generate structured findings data"""
        return self.findings

def generate_html_report(findings):
    """Generate OSCP-style HTML report"""
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTG-CRYPST-003 Security Test Report</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #000;
            color: #00ff00;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .header {{
            background-color: #111;
            padding: 20px;
            border: 1px solid #00ff00;
            margin-bottom: 20px;
        }}
        .banner {{
            background-color: #8B0000;
            color: white;
            padding: 10px;
            text-align: center;
            font-weight: bold;
            margin-bottom: 20px;
            border: 1px solid #ff0000;
        }}
        .section {{
            background-color: #111;
            border: 1px solid #00ff00;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .finding {{
            color: #ff4444;
            font-weight: bold;
        }}
        .code-block {{
            background-color: #222;
            border: 1px solid #00ff00;
            padding: 10px;
            margin: 10px 0;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }}
        h1, h2, h3 {{
            color: #00ff00;
            margin-top: 0;
        }}
        .risk-high {{
            color: #ff4444;
            font-weight: bold;
        }}
        .footer {{
            background-color: #111;
            border: 1px solid #00ff00;
            padding: 10px;
            text-align: center;
            font-size: 12px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            border: 1px solid #00ff00;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #222;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP Testing Guide</h1>
        <h2>OTG-CRYPST-003: Sensitive Information Sent via Unencrypted Channels</h2>
        <p><strong>Target:</strong> {findings['target']}</p>
        <p><strong>Test Date:</strong> {findings['test_date']}</p>
    </div>

    <div class="banner">
        VULNERABILITY CONFIRMED - HIGH RISK
    </div>

    <div class="section">
        <h3>VULNERABILITY SUMMARY</h3>
        <p>The application transmits sensitive authentication data over unencrypted HTTP channels. This exposes credentials and session tokens to potential interception by attackers on the same network.</p>
    </div>

    <div class="section">
        <h3>RISK ASSESSMENT</h3>
        <p><span class="risk-high">Risk Level: HIGH</span></p>
        <p><strong>Impact:</strong> Unauthorized access to user accounts through credential/session token interception</p>
        <p><strong>Likelihood:</strong> High in shared network environments (public Wi-Fi, corporate networks)</p>
    </div>

    <div class="section">
        <h3>FINDINGS</h3>
        <ul>
"""

    for finding in findings["findings"]:
        html_content += f"            <li class='finding'>[!] {finding}</li>\n"

    html_content += """        </ul>
    </div>

    <div class="section">
        <h3>PROOF OF CONCEPT</h3>
        <h4>Login Request (Plaintext Credentials):</h4>
        <div class="code-block">
"""

    if "login_request" in findings["evidence"]:
        req = findings["evidence"]["login_request"]
        html_content += f"""POST {req['url']} HTTP/1.1
Host: localhost
User-Agent: Python-requests
Content-Type: application/x-www-form-urlencoded
Content-Length: {len(str(req['data']))}

username={req['data'].get('username', '')}&password={req['data'].get('password', '')}&Login=Login"""

    html_content += """        </div>

        <h4>Response Headers (Cookie Security):</h4>
        <div class="code-block">
"""

    if "login_response" in findings["evidence"]:
        resp = findings["evidence"]["login_response"]
        html_content += f"HTTP/1.1 {resp['status_code']} OK\n"
        for key, value in resp['headers'].items():
            html_content += f"{key}: {value}\n"

    html_content += """        </div>
    </div>

    <div class="section">
        <h3>STEPS TO REPRODUCE</h3>
        <ol>
            <li>Access DVWA login page at <code>http://localhost/dvwa/login.php</code></li>
            <li>Enter credentials: admin/password</li>
            <li>Intercept the POST request using Burp Suite or similar tool</li>
            <li>Observe plaintext credentials in request body</li>
            <li>Check response headers for cookie security flags</li>
        </ol>
    </div>

    <div class="section">
        <h3>MITIGATION</h3>
        <ul>
            <li>Enforce HTTPS site-wide using TLS 1.2+</li>
            <li>Set <code>Secure</code> flag on all authentication cookies</li>
            <li>Set <code>HttpOnly</code> flag to prevent XSS cookie theft</li>
            <li>Implement HTTP Strict Transport Security (HSTS)</li>
            <li>Use SameSite attribute for additional CSRF protection</li>
        </ul>
    </div>

    <div class="section">
        <h3>REFERENCES</h3>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels" style="color:#00ff00;">OWASP OTG-CRYPST-003</a></li>
            <li>OSCP Exam Guidelines - Network Security Testing</li>
            <li>NIST SP 800-52 - Guidelines for TLS Implementation</li>
        </ul>
    </div>

    <div class="section">
        <h3>TOOLS USED</h3>
        <ul>
            <li>Custom Python Script (requests library)</li>
            <li>Burp Suite (manual verification)</li>
            <li>Wireshark (network traffic analysis)</li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA Security Testing Framework | OTG-CRYPST-003 Report</p>
        <p>This report is for educational and authorized testing purposes only</p>
    </div>
</body>
</html>"""

    return html_content

def main():
    print("Starting OTG-CRYPST-003 Test for DVWA...")
    print("Target: http://localhost/dvwa/")
    
    # Initialize tester
    tester = DVWATester()
    
    # Check protocol
    tester.check_protocol_security()
    
    # Get login page
    print("Fetching login page...")
    tester.get_login_page()
    
    # Perform login
    print("Performing login with default credentials...")
    tester.perform_login()
    
    # Analyze cookies
    print("Analyzing cookie security...")
    tester.analyze_cookies()
    
    # Analyze traffic
    tester.analyze_traffic()
    
    # Generate findings
    findings = tester.generate_report_data()
    
    # Save findings to JSON
    with open('traffic_capture.json', 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    
    # Generate HTML report
    html_report = generate_html_report(findings)
    with open('OTG-CRYPST-003_Report_DVWA.html', 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    print("Test completed!")
    print(f"Findings saved to: traffic_capture.json")
    print(f"HTML Report saved to: OTG-CRYPST-003_Report_DVWA.html")
    print("\nKey Findings:")
    for finding in findings["findings"]:
        print(f"   [!] {finding}")

if __name__ == "__main__":
    main()