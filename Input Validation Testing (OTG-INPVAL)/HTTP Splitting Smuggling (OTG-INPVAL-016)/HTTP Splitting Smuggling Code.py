#!/usr/bin/env python3
"""
DVWA HTTP Splitting/Smuggling Testing Script
OWASP OTG-INPVAL-016 Compliance
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
import socket
from urllib.parse import urljoin, urlparse

# Disable SSL warnings for localhost testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DVWAHTTPSplittingSmugglingTester:
    def __init__(self, base_url, username, password, output_file, timeout=15, delay=1):
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
        self.tested_payloads = []  # Store all tested payloads for reporting
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
        """Discover endpoints that might be vulnerable to HTTP splitting/smuggling"""
        print("[*] Discovering endpoints for HTTP splitting/smuggling...")
        
        # DVWA modules that might reflect user input
        dvwa_modules = [
            'vulnerabilities/xss_r/',     # Reflected XSS (might reflect in headers)
            'vulnerabilities/exec/',      # Command Execution
            'vulnerabilities/sqli/',      # SQL Injection
            'vulnerabilities/fi/',        # File Inclusion
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
                            if param_name:
                                params.append({
                                    'name': param_name,
                                    'type': param_type
                                })
                        
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
                            print(f"[+] Found endpoint: {full_action} with params: {param_names}")
                
            except Exception as e:
                print(f"[-] Error checking module {module}: {e}")
        
        print(f"[+] Discovered {len(self.endpoints)} endpoints")
    
    def send_raw_http_request(self, host, port, request):
        """Send raw HTTP request for smuggling tests"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.send(request.encode())
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except socket.timeout:
                    break
            sock.close()
            return response.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"[-] Error sending raw HTTP request: {e}")
            return ""
    
    def test_http_response_splitting(self):
        """Test HTTP Response Splitting vulnerabilities"""
        print("[*] Testing HTTP Response Splitting...")
        
        # HTTP Response Splitting payloads
        splitting_payloads = [
            {
                'name': 'Basic CRLF Injection',
                'payload': '%0D%0ASet-Cookie:test=splitting',
                'expected': 'Set-Cookie: test=splitting',
                'type': 'CRLF Injection',
                'vector': 'URL Parameter'
            },
            {
                'name': 'Header Injection',
                'payload': '%0D%0AX-Test-Header:Injected',
                'expected': 'X-Test-Header: Injected',
                'type': 'Header Injection',
                'vector': 'URL Parameter'
            },
            {
                'name': 'Location Redirect',
                'payload': '%0D%0ALocation:http://example.com',
                'expected': 'Location: http://example.com',
                'type': 'Redirect Injection',
                'vector': 'URL Parameter'
            },
            {
                'name': 'Content-Type Injection',
                'payload': '%0D%0AContent-Type:text/plain',
                'expected': 'Content-Type: text/plain',
                'type': 'Content-Type Injection',
                'vector': 'URL Parameter'
            }
        ]
        
        # Test each endpoint with splitting payloads
        for endpoint in self.endpoints:
            url = endpoint['url']
            parameters = endpoint['parameters']
            module = endpoint['module']
            method = endpoint['method']
            
            print(f"[*] Testing HTTP Splitting on: {url}")
            
            # Find text parameters for testing
            test_param = None
            for param in parameters:
                if param['type'] in ['text', 'textarea', 'search']:
                    test_param = param['name']
                    break
            
            # Fallback: use first available parameter
            if not test_param and parameters:
                test_param = parameters[0]['name']
            
            if not test_param:
                print("[-] No suitable parameter found for testing")
                continue
            
            print(f"[*] Using parameter: {test_param}")
            
            # Test each splitting payload
            for payload_info in splitting_payloads:
                payload_name = payload_info['name']
                payload_value = payload_info['payload']
                expected_result = payload_info['expected']
                splitting_type = payload_info['type']
                vector = payload_info['vector']
                
                # Store payload for reporting
                self.tested_payloads.append({
                    'name': payload_name,
                    'payload': payload_value,
                    'type': splitting_type,
                    'vector': vector,
                    'category': 'HTTP Response Splitting'
                })
                
                try:
                    print(f"  [*] Testing {payload_name}")
                    
                    # Respect delay between requests
                    time.sleep(self.delay)
                    
                    # Create data with payload
                    if method.upper() == 'GET':
                        params = {test_param: payload_value}
                        response = self.session.get(url, params=params, verify=False, timeout=self.timeout)
                    else:
                        data = {test_param: payload_value}
                        response = self.session.post(url, data=data, verify=False, timeout=self.timeout)
                    
                    # Analyze response for splitting indicators
                    result = {
                        'url': url,
                        'module': module,
                        'vuln_type': 'HTTP Response Splitting',
                        'parameter': test_param,
                        'payload_name': payload_name,
                        'payload': payload_value,
                        'vector': vector,
                        'attack_type': splitting_type,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'vulnerable': False,
                        'description': '',
                        'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text,
                        'headers': str(dict(response.headers))
                    }
                    
                    # Check for splitting indicators in headers and response
                    response_text = response.text.lower()
                    response_headers = str(dict(response.headers)).lower()
                    
                    if expected_result.lower() in response_headers or expected_result.lower() in response_text:
                        result['vulnerable'] = True
                        result['description'] = f"Found expected header injection: {expected_result}"
                    
                    # Additional checks for common splitting indicators
                    splitting_indicators = [
                        'set-cookie:',
                        'location:',
                        'content-type:',
                        'x-test-header:',
                        '\r\n\r\n'
                    ]
                    
                    for indicator in splitting_indicators:
                        if indicator in response_headers and not result['vulnerable']:
                            result['vulnerable'] = True
                            result['description'] = f"Found splitting indicator in headers: {indicator}"
                            break
                    
                    self.results.append(result)
                    
                    if result['vulnerable']:
                        print(f"  [+] VULNERABLE: {payload_name} - {result['description']}")
                    else:
                        print(f"  [-] NOT VULNERABLE: {payload_name}")
                    
                except Exception as e:
                    print(f"  [-] Error testing {payload_name}: {e}")
                    self.results.append({
                        'url': url,
                        'module': module,
                        'vuln_type': 'HTTP Response Splitting',
                        'parameter': test_param,
                        'payload_name': payload_name,
                        'payload': payload_value,
                        'vector': vector,
                        'attack_type': splitting_type,
                        'status_code': 0,
                        'response_length': 0,
                        'vulnerable': False,
                        'description': f'Error: {str(e)}',
                        'error': True
                    })
    
    def test_http_request_smuggling(self):
        """Test HTTP Request Smuggling vulnerabilities"""
        print("[*] Testing HTTP Request Smuggling...")
        
        # Parse target URL for raw socket connection
        parsed_url = urlparse(self.base_url)
        host = parsed_url.hostname or 'localhost'
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        print(f"[*] Testing raw HTTP connection to {host}:{port}")
        
        # HTTP Smuggling payloads
        smuggling_payloads = [
            {
                'name': 'CL.TE Smuggling',
                'request': f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
                'expected': 'HTTP/1.1',
                'type': 'CL.TE',
                'description': 'Content-Length vs Transfer-Encoding conflict'
            },
            {
                'name': 'TE.CL Smuggling',
                'request': f"POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG",
                'expected': 'HTTP/1.1',
                'type': 'TE.CL',
                'description': 'Transfer-Encoding vs Content-Length conflict'
            },
            {
                'name': 'Chunked Smuggling',
                'request': f"GET / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                'expected': 'HTTP/1.1',
                'type': 'Chunked',
                'description': 'Malformed chunked encoding'
            }
        ]
        
        # Test each smuggling payload
        for payload_info in smuggling_payloads:
            payload_name = payload_info['name']
            raw_request = payload_info['request']
            expected_result = payload_info['expected']
            smuggling_type = payload_info['type']
            description = payload_info['description']
            
            # Store payload for reporting
            self.tested_payloads.append({
                'name': payload_name,
                'payload': raw_request[:100] + '...' if len(raw_request) > 100 else raw_request,
                'type': smuggling_type,
                'vector': 'Raw HTTP Request',
                'category': 'HTTP Request Smuggling'
            })
            
            try:
                print(f"  [*] Testing {payload_name}")
                
                # Respect delay between requests
                time.sleep(self.delay)
                
                # Send raw HTTP request
                response = self.send_raw_http_request(host, port, raw_request)
                
                # Analyze response for smuggling indicators
                result = {
                    'url': f"{host}:{port}",
                    'module': 'Raw HTTP',
                    'vuln_type': 'HTTP Request Smuggling',
                    'parameter': 'N/A',
                    'payload_name': payload_name,
                    'payload': raw_request[:100] + '...' if len(raw_request) > 100 else raw_request,
                    'vector': 'Raw HTTP Request',
                    'attack_type': smuggling_type,
                    'status_code': 'N/A',
                    'response_length': len(response),
                    'vulnerable': False,
                    'description': description,
                    'response_preview': response[:300] + '...' if len(response) > 300 else response
                }
                
                # Check for smuggling indicators
                response_lower = response.lower()
                
                if expected_result.lower() in response_lower:
                    # Look for multiple HTTP responses or unusual patterns
                    if response.count('HTTP/1.1') > 1 or response.count('\r\n\r\n') > 1:
                        result['vulnerable'] = True
                        result['description'] = f"Multiple HTTP responses detected - potential smuggling: {description}"
                
                # Additional checks for smuggling indicators
                smuggling_indicators = [
                    'http/1.1 200',
                    'transfer-encoding:',
                    'content-length:',
                    'connection: close'
                ]
                
                indicator_count = sum(1 for indicator in smuggling_indicators if indicator in response_lower)
                if indicator_count > 2 and not result['vulnerable']:
                    result['vulnerable'] = True
                    result['description'] = f"Multiple HTTP indicators detected - potential smuggling: {description}"
                
                self.results.append(result)
                
                if result['vulnerable']:
                    print(f"  [+] POTENTIALLY VULNERABLE: {payload_name} - {result['description']}")
                else:
                    print(f"  [-] NOT VULNERABLE: {payload_name}")
                    
            except Exception as e:
                print(f"  [-] Error testing {payload_name}: {e}")
                self.results.append({
                    'url': f"{host}:{port}",
                    'module': 'Raw HTTP',
                    'vuln_type': 'HTTP Request Smuggling',
                    'parameter': 'N/A',
                    'payload_name': payload_name,
                    'payload': raw_request[:100] + '...' if len(raw_request) > 100 else raw_request,
                    'vector': 'Raw HTTP Request',
                    'attack_type': smuggling_type,
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
        
        # Separate results by vulnerability type
        splitting_results = [r for r in self.results if r.get('vuln_type') == 'HTTP Response Splitting']
        smuggling_results = [r for r in self.results if r.get('vuln_type') == 'HTTP Request Smuggling']
        
        splitting_vuln = sum(1 for r in splitting_results if r.get('vulnerable', False))
        smuggling_vuln = sum(1 for r in smuggling_results if r.get('vulnerable', False))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTTP Splitting/Smuggling Assessment - DVWA (OTG-INPVAL-016)</title>
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
        .tab {{
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 5px 5px 0 0;
        }}
        .tab button {{
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 16px;
        }}
        .tab button:hover {{
            background-color: #ddd;
        }}
        .tab button.active {{
            background-color: #2a5298;
            color: white;
        }}
        .tabcontent {{
            display: none;
            padding: 20px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 5px 5px;
            background-color: white;
        }}
        .payload-table {{
            font-size: 0.9em;
        }}
        .payload-table th, .payload-table td {{
            padding: 8px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>HTTP Splitting/Smuggling Assessment</h1>
        <p>DVWA Security Test - OWASP Testing Guide OTG-INPVAL-016</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
            <p>This assessment identified <span class="risk-high">{vulnerable_count} HTTP Splitting/Smuggling vulnerabilities</span> in the DVWA application. HTTP Splitting and Smuggling are advanced web vulnerabilities that can lead to cache poisoning, session fixation, and bypass of security controls by manipulating HTTP requests and responses.</p>
        </div>
        <div class="findings-summary">
            <div class="finding-item finding-vuln">
                <h3>{vulnerable_count}</h3>
                <p>Total Vulnerabilities</p>
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
                <td>HTTP Splitting/Smuggling</td>
            </tr>
            <tr>
                <td><strong>OWASP Test ID</strong></td>
                <td>OTG-INPVAL-016</td>
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
        <p>The testing methodology followed the OWASP Testing Guide for HTTP Splitting/Smuggling:</p>
        <ol>
            <li><strong>Authentication</strong>: Logged into DVWA with provided credentials</li>
            <li><strong>Endpoint Discovery</strong>: Identified modules that process user input potentially in HTTP headers</li>
            <li><strong>HTTP Response Splitting Testing</strong>: Tested CRLF injection and header manipulation payloads</li>
            <li><strong>HTTP Request Smuggling Testing</strong>: Tested raw HTTP requests with conflicting headers</li>
            <li><strong>Analysis</strong>: Documented vulnerable endpoints and payloads</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">Tested Payloads</h2>
        <p>The following payloads were tested during the assessment:</p>
        <table class="payload-table">
            <thead>
                <tr>
                    <th>Payload Name</th>
                    <th>Category</th>
                    <th>Type</th>
                    <th>Vector</th>
                    <th>Payload</th>
                </tr>
            </thead>
            <tbody>"""
        
        # Add tested payloads to report
        for payload in self.tested_payloads:
            # Truncate long payloads for display
            display_payload = payload.get('payload', 'N/A')
            if len(display_payload) > 80:
                display_payload = display_payload[:77] + "..."
            
            html_content += f"""
                <tr>
                    <td>{html.escape(payload.get('name', 'N/A'))}</td>
                    <td>{html.escape(payload.get('category', 'N/A'))}</td>
                    <td>{html.escape(payload.get('type', 'N/A'))}</td>
                    <td>{html.escape(payload.get('vector', 'N/A'))}</td>
                    <td><code>{html.escape(display_payload)}</code></td>
                </tr>"""
        
        html_content += f"""
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Vulnerability Summary</h2>
        <div class="findings-summary">
            <div class="finding-item finding-vuln">
                <h3>{splitting_vuln}</h3>
                <p>HTTP Response Splitting</p>
            </div>
            <div class="finding-item finding-vuln">
                <h3>{smuggling_vuln}</h3>
                <p>HTTP Request Smuggling</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Detailed Findings</h2>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'splitting')">HTTP Response Splitting</button>
            <button class="tablinks" onclick="openTab(event, 'smuggling')">HTTP Request Smuggling</button>
        </div>

        <div id="splitting" class="tabcontent" style="display:block">
            <h3>HTTP Response Splitting Results</h3>
            <p>The following HTTP Response Splitting tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Attack Type</th>
                        <th>Payload Name</th>
                        <th>Status</th>
                        <th>Status Code</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # HTTP Response Splitting results
        for result in splitting_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('module', 'Unknown'))}</td>
                        <td>{html.escape(result.get('attack_type', 'N/A'))}</td>
                        <td>{html.escape(result.get('payload_name', 'N/A'))}</td>
                        <td><span class="{status_class}">{status_text}</span></td>
                        <td>{result.get('status_code', 'N/A')}</td>
                    </tr>"""
            
            # Add description row if vulnerable
            if result.get('vulnerable', False):
                html_content += f"""
                    <tr>
                        <td colspan="5" style="background-color: #fff3e0;">
                            <strong>Description:</strong> {html.escape(result.get('description', ''))}<br>
                            <strong>Payload:</strong> {html.escape(result.get('payload', ''))}
                        </td>
                    </tr>"""
        
        html_content += f"""
                </tbody>
            </table>
            
            <h4>HTTP Response Splitting Vulnerabilities</h4>"""
        
        # Show only vulnerable HTTP Response Splitting results
        vulnerable_splitting_results = [r for r in splitting_results if r.get('vulnerable', False)]
        
        if vulnerable_splitting_results:
            for i, result in enumerate(vulnerable_splitting_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
Attack Type: {html.escape(result.get('attack_type', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No HTTP Response Splitting vulnerabilities were found.</p>"""
        
        html_content += """
        </div>

        <div id="smuggling" class="tabcontent">
            <h3>HTTP Request Smuggling Results</h3>
            <p>The following HTTP Request Smuggling tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Attack Type</th>
                        <th>Payload Name</th>
                        <th>Status</th>
                        <th>Response Length</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # HTTP Request Smuggling results
        for result in smuggling_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('url', 'N/A'))}</td>
                        <td>{html.escape(result.get('attack_type', 'N/A'))}</td>
                        <td>{html.escape(result.get('payload_name', 'N/A'))}</td>
                        <td><span class="{status_class}">{status_text}</span></td>
                        <td>{result.get('response_length', 'N/A')}</td>
                    </tr>"""
            
            # Add description row if vulnerable
            if result.get('vulnerable', False):
                html_content += f"""
                    <tr>
                        <td colspan="5" style="background-color: #fff3e0;">
                            <strong>Description:</strong> {html.escape(result.get('description', ''))}<br>
                            <strong>Payload:</strong> {html.escape(result.get('payload', ''))}
                        </td>
                    </tr>"""
        
        html_content += f"""
                </tbody>
            </table>
            
            <h4>HTTP Request Smuggling Vulnerabilities</h4>"""
        
        # Show only vulnerable HTTP Request Smuggling results
        vulnerable_smuggling_results = [r for r in smuggling_results if r.get('vulnerable', False)]
        
        if vulnerable_smuggling_results:
            for i, result in enumerate(vulnerable_smuggling_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Target: {html.escape(result.get('url', 'N/A'))}
Attack Type: {html.escape(result.get('attack_type', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Description: {html.escape(result.get('description', ''))}
Response Length: {result.get('response_length', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No HTTP Request Smuggling vulnerabilities were found.</p>"""
        
        html_content += """
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">HTTP Splitting/Smuggling Explained</h2>
        
        <h3>HTTP Response Splitting</h3>
        <p>HTTP Response Splitting occurs when an application reflects user input in HTTP response headers without proper validation. Attackers can inject CRLF (%0D%0A) sequences to split the response and inject additional headers or content.</p>
        <ul>
            <li><strong>CRLF Injection</strong>: Using %0D%0A to inject new headers</li>
            <li><strong>Header Manipulation</strong>: Injecting Set-Cookie, Location, or Content-Type headers</li>
            <li><strong>Cache Poisoning</strong>: Storing malicious content in web caches</li>
            <li><strong>Session Fixation</strong>: Forcing users to use attacker-controlled session IDs</li>
        </ul>
        
        <h3>HTTP Request Smuggling</h3>
        <p>HTTP Request Smuggling exploits discrepancies in how different servers (frontend/backend) parse HTTP requests, particularly when Content-Length and Transfer-Encoding headers conflict.</p>
        <ul>
            <li><strong>CL.TE Smuggling</strong>: Frontend uses Content-Length, backend uses Transfer-Encoding</li>
            <li><strong>TE.CL Smuggling</strong>: Frontend uses Transfer-Encoding, backend uses Content-Length</li>
            <li><strong>Bypass Security Controls</strong>: Smuggling requests to bypass authentication or WAF</li>
            <li><strong>Session Hijacking</strong>: Capturing other users' requests/responses</li>
        </ul>
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Recommendations</h2>
        <p>To prevent HTTP Splitting/Smuggling vulnerabilities, implement the following measures:</p>
        
        <h3>Input Validation and Sanitization</h3>
        <ol>
            <li><strong>Filter CRLF Characters</strong>: Remove or encode %0D%0A sequences from user input</li>
            <li><strong>Validate Headers</strong>: Ensure user input doesn't contain header-like patterns</li>
            <li><strong>Whitelist Approach</strong>: Only allow known good input patterns</li>
            <li><strong>Content-Type Validation</strong>: Validate and restrict content types</li>
        </ol>
        
        <h3>Secure HTTP Processing</h3>
        <ol>
            <li><strong>Consistent Parsing</strong>: Ensure all servers parse HTTP requests consistently</li>
            <li><strong>Header Normalization</strong>: Normalize conflicting headers before processing</li>
            <li><strong>Disable Unnecessary Features</strong>: Disable chunked encoding if not required</li>
            <li><strong>Use Modern HTTP Versions</strong>: Prefer HTTP/2 which eliminates many smuggling issues</li>
        </ol>
        
        <h3>Web Server Configuration</h3>
        <ol>
            <li><strong>Web Application Firewall</strong>: Implement WAF rules to detect splitting/smuggling attempts</li>
            <li><strong>Load Balancer Configuration</strong>: Ensure consistent header processing across infrastructure</li>
            <li><strong>Request Monitoring</strong>: Monitor for unusual HTTP patterns</li>
            <li><strong>Security Headers</strong>: Implement proper security headers to prevent injection</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Splitting_Smuggling">OWASP Testing Guide - OTG-INPVAL-016</a></li>
            <li><a href="https://owasp.org/www-community/attacks/HTTP_Response_Splitting">OWASP HTTP Response Splitting</a></li>
            <li><a href="https://owasp.org/www-community/attacks/HTTP_Request_Smuggling">OWASP HTTP Request Smuggling</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/113.html">CWE-113: HTTP Response Splitting</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/444.html">CWE-444: HTTP Request Smuggling</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA) Documentation</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA HTTP Splitting/Smuggling Testing Script | OWASP/OSCP-Style Report</p>
        <p>Report generated on: {timestamp}</p>
    </div>

    <script>
        function openTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].style.display = "none";
            }}
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }}
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }}
    </script>
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
        print("=== DVWA HTTP Splitting/Smuggling Testing Script ===")
        print(f"Target: {self.base_url}")
        print(f"Output: {self.output_file}")
        print(f"Request delay: {self.delay}s")
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
        
        # Test HTTP Response Splitting
        self.test_http_response_splitting()
        
        # Test HTTP Request Smuggling
        self.test_http_request_smuggling()
        
        # Generate report
        self.generate_html_report()
        
        # Summary
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        splitting_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'HTTP Response Splitting' and r.get('vulnerable', False))
        smuggling_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'HTTP Request Smuggling' and r.get('vulnerable', False))
        
        total_tests = len(self.results)
        print(f"\n=== Test Summary ===")
        print(f"Total endpoints tested: {len(self.endpoints)}")
        print(f"Total tests conducted: {total_tests}")
        print(f"HTTP Response Splitting vulnerabilities: {splitting_vuln}")
        print(f"HTTP Request Smuggling vulnerabilities: {smuggling_vuln}")
        print(f"Total vulnerabilities: {vulnerable_count}")
        print(f"Security status: {'VULNERABLE' if vulnerable_count > 0 else 'SECURE'}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='DVWA HTTP Splitting/Smuggling Testing Script (OTG-INPVAL-016)')
    parser.add_argument('--url', default='http://localhost/dvwa', help='DVWA base URL (default: http://localhost/dvwa)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('--output', default='reports/http_splitting_smuggling_report.html', help='Output HTML report file (default: reports/http_splitting_smuggling_report.html)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = DVWAHTTPSplittingSmugglingTester(
        args.url, 
        args.username, 
        args.password, 
        args.output, 
        args.timeout, 
        args.delay
    )
    
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