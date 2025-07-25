#!/usr/bin/env python3
"""
DVWA HTTP Verb Tampering Testing Script
OWASP OTG-INPVAL-003 Compliance
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

class DVWAHTTPVerbTamperingTester:
    def __init__(self, base_url, username, password, output_file, timeout=10):
        self.base_url = base_url.rstrip('/')
        self.login_url = urljoin(self.base_url + '/', 'login.php')
        self.timeout = timeout
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
        """Discover form endpoints in DVWA"""
        print("[*] Discovering form endpoints...")
        
        # Common DVWA modules to test
        dvwa_modules = [
            'vulnerabilities/exec/',      # Command Execution
            'vulnerabilities/xss_r/',     # Reflected XSS
            'vulnerabilities/xss_s/',     # Stored XSS
            'vulnerabilities/sqli/',      # SQL Injection
            'vulnerabilities/sqli_blind/', # Blind SQL Injection
            'vulnerabilities/upload/',    # File Upload
            'vulnerabilities/captcha/',   # CAPTCHA
            'vulnerabilities/weak_id/',   # Weak Session IDs
            'vulnerabilities/csp/'        # Content Security Policy
        ]
        
        for module in dvwa_modules:
            module_url = urljoin(self.base_url + '/', module)
            try:
                print(f"[*] Checking module: {module}")
                response = self.session.get(module_url, verify=False, timeout=self.timeout)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all forms in the page
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
                            if param_name:
                                params.append(param_name)
                        
                        endpoint_info = {
                            'url': full_action,
                            'original_method': method,
                            'parameters': params,
                            'module': module
                        }
                        
                        # Avoid duplicates
                        if endpoint_info not in self.endpoints:
                            self.endpoints.append(endpoint_info)
                            print(f"[+] Found endpoint: {full_action} ({method})")
                
            except Exception as e:
                print(f"[-] Error checking module {module}: {e}")
        
        # Also check the login page
        try:
            login_response = self.session.get(self.login_url, verify=False, timeout=self.timeout)
            if login_response.status_code == 200:
                soup = BeautifulSoup(login_response.text, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    
                    if action:
                        full_action = urljoin(self.login_url, action)
                    else:
                        full_action = self.login_url
                    
                    params = []
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        param_name = input_field.get('name')
                        if param_name:
                            params.append(param_name)
                    
                    endpoint_info = {
                        'url': full_action,
                        'original_method': method,
                        'parameters': params,
                        'module': 'login'
                    }
                    
                    if endpoint_info not in self.endpoints:
                        self.endpoints.append(endpoint_info)
                        print(f"[+] Found login endpoint: {full_action} ({method})")
        except Exception as e:
            print(f"[-] Error checking login page: {e}")
        
        print(f"[+] Discovered {len(self.endpoints)} endpoints")
    
    def test_http_verbs(self):
        """Test HTTP verb tampering on discovered endpoints"""
        print("[*] Testing HTTP verb tampering...")
        
        # HTTP methods to test
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE']
        
        for endpoint in self.endpoints:
            url = endpoint['url']
            original_method = endpoint['original_method']
            parameters = endpoint['parameters']
            module = endpoint['module']
            
            print(f"[*] Testing endpoint: {url} (original: {original_method})")
            
            # Create sample data for POST requests
            sample_data = {}
            for param in parameters:
                if 'name' in param.lower():
                    sample_data[param] = 'test'
                elif 'cmd' in param.lower() or 'command' in param.lower():
                    sample_data[param] = 'whoami'
                elif 'ip' in param.lower():
                    sample_data[param] = '127.0.0.1'
                elif 'text' in param.lower() or 'message' in param.lower():
                    sample_data[param] = 'test message'
                else:
                    sample_data[param] = 'test'
            
            # Test each HTTP method
            for method in http_methods:
                try:
                    print(f"  [*] Testing {method}...")
                    
                    # Prepare request based on method
                    if method == 'GET':
                        response = self.session.get(url, params=sample_data, verify=False, timeout=self.timeout)
                    elif method == 'POST':
                        response = self.session.post(url, data=sample_data, verify=False, timeout=self.timeout)
                    elif method == 'PUT':
                        response = self.session.put(url, data=sample_data, verify=False, timeout=self.timeout)
                    elif method == 'DELETE':
                        response = self.session.delete(url, data=sample_data, verify=False, timeout=self.timeout)
                    elif method == 'OPTIONS':
                        response = self.session.options(url, verify=False, timeout=self.timeout)
                    elif method == 'HEAD':
                        response = self.session.head(url, verify=False, timeout=self.timeout)
                    elif method == 'PATCH':
                        response = self.session.patch(url, data=sample_data, verify=False, timeout=self.timeout)
                    elif method == 'TRACE':
                        response = self.session.request('TRACE', url, verify=False, timeout=self.timeout)
                    
                    # Analyze response
                    result = {
                        'url': url,
                        'module': module,
                        'original_method': original_method,
                        'test_method': method,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'vulnerable': False,
                        'description': ''
                    }
                    
                    # Check for vulnerabilities
                    if method != original_method:
                        # Different method was used
                        if response.status_code == 200 and len(response.text) > 100:
                            # Method worked and returned content
                            result['vulnerable'] = True
                            result['description'] = f"Method {method} allowed and returned content"
                        elif method in ['PUT', 'DELETE', 'PATCH'] and response.status_code in [200, 201, 204]:
                            # State-changing method was allowed
                            result['vulnerable'] = True
                            result['description'] = f"Dangerous method {method} allowed with status {response.status_code}"
                        elif method == 'OPTIONS' and 'Allow' in response.headers:
                            # OPTIONS returned allowed methods
                            allowed_methods = response.headers.get('Allow', '')
                            if original_method not in allowed_methods:
                                result['vulnerable'] = True
                                result['description'] = f"OPTIONS reveals unexpected methods: {allowed_methods}"
                    
                    self.results.append(result)
                    
                    if result['vulnerable']:
                        print(f"  [+] VULNERABLE: {method} on {url} - {result['description']}")
                    
                except Exception as e:
                    print(f"  [-] Error testing {method} on {url}: {e}")
                    self.results.append({
                        'url': url,
                        'module': module,
                        'original_method': original_method,
                        'test_method': method,
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
    <title>HTTP Verb Tampering Assessment - DVWA (OTG-INPVAL-003)</title>
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
        <h1>HTTP Verb Tampering Assessment</h1>
        <p>DVWA Security Test - OWASP Testing Guide OTG-INPVAL-003</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
            <p>This assessment identified <span class="risk-high">{vulnerable_count} HTTP Verb Tampering vulnerabilities</span> in the DVWA application. HTTP Verb Tampering occurs when web applications accept unexpected HTTP methods, potentially leading to authentication bypass, unauthorized data access, or other security issues.</p>
        </div>
        <div class="findings-summary">
            <div class="finding-item finding-vuln">
                <h3>{vulnerable_count}</h3>
                <p>Vulnerable Endpoints</p>
            </div>
            <div class="finding-item finding-safe">
                <h3>{len(self.results) - vulnerable_count}</h3>
                <p>Secure Endpoints</p>
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
                <td>HTTP Verb Tampering</td>
            </tr>
            <tr>
                <td><strong>OWASP Test ID</strong></td>
                <td>OTG-INPVAL-003</td>
            </tr>
            <tr>
                <td><strong>Risk Level</strong></td>
                <td><span class="risk-medium">Medium to High</span></td>
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
        <p>The testing methodology followed the OWASP Testing Guide for HTTP Verb Tampering:</p>
        <ol>
            <li><strong>Authentication</strong>: Logged into DVWA with provided credentials</li>
            <li><strong>Endpoint Discovery</strong>: Identified form endpoints throughout DVWA modules</li>
            <li><strong>Verb Testing</strong>: Tested all HTTP methods (GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH, TRACE) against each endpoint</li>
            <li><strong>Analysis</strong>: Documented endpoints that accepted unexpected HTTP methods</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">Findings</h2>
        <p>The following endpoints were tested for HTTP verb tampering:</p>
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Endpoint</th>
                    <th>Original Method</th>
                    <th>Test Method</th>
                    <th>Status</th>
                    <th>Result</th>
                </tr>
            </thead>
            <tbody>"""
        
        # Sort results by vulnerability status
        sorted_results = sorted(self.results, key=lambda x: (not x.get('vulnerable', False), x['url'], x['test_method']))
        
        for result in sorted_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            # Truncate long URLs
            display_url = result['url'] if len(result['url']) < 50 else result['url'][:47] + "..."
            
            html_content += f"""
                <tr>
                    <td>{html.escape(result.get('module', 'Unknown'))}</td>
                    <td><code>{html.escape(display_url)}</code></td>
                    <td>{html.escape(result.get('original_method', 'N/A'))}</td>
                    <td>{html.escape(result.get('test_method', 'N/A'))}</td>
                    <td>{result.get('status_code', 'N/A')}</td>
                    <td><span class="{status_class}">{status_text}</span></td>
                </tr>"""
            
            # Add description row if vulnerable
            if result.get('vulnerable', False):
                html_content += f"""
                <tr>
                    <td colspan="6" style="background-color: #fff3e0;">
                        <strong>Description:</strong> {html.escape(result.get('description', ''))}
                    </td>
                </tr>"""
        
        html_content += f"""
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Detailed Vulnerabilities</h2>
        <p>The following HTTP Verb Tampering vulnerabilities were identified:</p>"""
        
        # Show only vulnerable results with details
        vulnerable_results = [r for r in self.results if r.get('vulnerable', False)]
        
        if vulnerable_results:
            for i, result in enumerate(vulnerable_results, 1):
                html_content += f"""
        <div class="code">
<strong>Vulnerability #{i}</strong>
Endpoint: {html.escape(result['url'])}
Module: {html.escape(result.get('module', 'Unknown'))}
Original Method: {html.escape(result.get('original_method', 'N/A'))}
Tested Method: {html.escape(result.get('test_method', 'N/A'))}
Status Code: {result.get('status_code', 'N/A')}
Description: {html.escape(result.get('description', ''))}
        </div>"""
        else:
            html_content += """
        <p>No HTTP Verb Tampering vulnerabilities were found in the tested endpoints.</p>"""
        
        html_content += f"""
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Recommendations</h2>
        <p>To prevent HTTP Verb Tampering vulnerabilities, implement the following measures:</p>
        <ol>
            <li><strong>Strict Method Validation</strong>: Only accept expected HTTP methods for each endpoint</li>
            <li><strong>CSRF Protection</strong>: Implement CSRF tokens for state-changing operations regardless of HTTP method</li>
            <li><strong>Access Controls</strong>: Enforce proper authentication and authorization for all HTTP methods</li>
            <li><strong>Disable Unnecessary Methods</strong>: Explicitly disable HTTP methods not required by the application</li>
            <li><strong>Web Server Configuration</strong>: Configure web servers to reject unexpected HTTP methods</li>
            <li><strong>Regular Security Testing</strong>: Conduct periodic security assessments including HTTP verb testing</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering">OWASP Testing Guide - OTG-INPVAL-003</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/444.html">CWE-444: Inconsistent Interpretation of HTTP Requests</a></li>
            <li><a href="https://owasp.org/www-community/attacks/HTTP_Verb_Tampering">OWASP HTTP Verb Tampering</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA) Documentation</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA HTTP Verb Tampering Testing Script | OWASP/OSCP-Style Report</p>
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
        print("=== DVWA HTTP Verb Tampering Testing Script ===")
        print(f"Target: {self.base_url}")
        print(f"Output: {self.output_file}")
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
        
        # Test HTTP verbs
        self.test_http_verbs()
        
        # Generate report
        self.generate_html_report()
        
        # Summary
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        print(f"\n=== Test Summary ===")
        print(f"Total endpoints tested: {len(self.endpoints)}")
        print(f"Total HTTP method tests: {len(self.results)}")
        print(f"Vulnerable cases: {vulnerable_count}")
        print(f"Security status: {'VULNERABLE' if vulnerable_count > 0 else 'SECURE'}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='DVWA HTTP Verb Tampering Testing Script (OTG-INPVAL-003)')
    parser.add_argument('--url', default='http://localhost/dvwa', help='DVWA base URL (default: http://localhost/dvwa)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('--output', default='reports/http_verb_tampering_report.html', help='Output HTML report file (default: reports/http_verb_tampering_report.html)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = DVWAHTTPVerbTamperingTester(args.url, args.username, args.password, args.output, args.timeout)
    
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