#!/usr/bin/env python3
"""
DVWA Incubated Vulnerabilities Testing Script
OWASP OTG-INPVAL-015 Compliance
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

class DVWAIncubatedVulnerabilitiesTester:
    def __init__(self, base_url, username, password, output_file, timeout=15, delay=1, verification_delay=5):
        self.base_url = base_url.rstrip('/')
        self.login_url = urljoin(self.base_url + '/', 'login.php')
        self.timeout = timeout
        self.delay = delay
        self.verification_delay = verification_delay
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
        print(f"[*] Verification delay: {self.verification_delay}s")
        
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
                # Save page content for debugging
                with open('debug_page.html', 'w', encoding='utf-8') as f:
                    f.write(response.text)
                print("[-] Saved page content to debug_page.html for inspection")
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
        """Discover endpoints that support incubated vulnerabilities in DVWA"""
        print("[*] Discovering endpoints for incubated vulnerabilities...")
        
        # DVWA modules that support incubated vulnerabilities
        dvwa_modules = [
            'vulnerabilities/xss_s/',     # Stored XSS (Guestbook)
            'vulnerabilities/upload/',    # File Upload
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
    
    def test_stored_xss(self):
        """Test Stored XSS (Incubated XSS)"""
        print("[*] Testing Stored XSS (Incubated Vulnerabilities)...")
        
        # Find Stored XSS endpoint (Guestbook)
        xss_endpoint = None
        for endpoint in self.endpoints:
            if 'xss_s' in endpoint['module']:
                xss_endpoint = endpoint
                break
        
        if not xss_endpoint:
            print("[-] Stored XSS endpoint not found")
            return
        
        url = xss_endpoint['url']
        parameters = xss_endpoint['parameters']
        module = xss_endpoint['module']
        method = xss_endpoint['method']
        
        print(f"[*] Testing Stored XSS on: {url}")
        print(f"[*] Available parameters: {[p['name'] for p in parameters]}")
        
        # Stored XSS payloads
        xss_payloads = [
            {
                'name': 'Basic Script Tag',
                'payload': '<script>alert("INCUBATED-XSS")</script>',
                'expected': 'INCUBATED-XSS',
                'type': 'Stored XSS',
                'vector': 'script_tag'
            },
            {
                'name': 'Image OnError',
                'payload': '<img src="x" onerror="alert(\'XSS\')">',
                'expected': 'XSS',
                'type': 'Stored XSS',
                'vector': 'img_onerror'
            },
            {
                'name': 'SVG Payload',
                'payload': '<svg/onload=alert("XSS")>',
                'expected': 'XSS',
                'type': 'Stored XSS',
                'vector': 'svg_onload'
            }
        ]
        
        # Find text parameters for XSS testing
        name_param = None
        message_param = None
        
        for param in parameters:
            param_name = param['name'].lower()
            if 'name' in param_name:
                name_param = param['name']
            elif 'message' in param_name or 'text' in param_name or 'comment' in param_name or 'mtx' in param_name:
                message_param = param['name']
        
        # Fallback: use first available parameters
        if not name_param and parameters:
            name_param = parameters[0]['name']
        if not message_param and len(parameters) > 1:
            message_param = parameters[1]['name']
        elif not message_param and parameters:
            message_param = parameters[0]['name']
        
        if not name_param or not message_param:
            print("[-] Required parameters for Stored XSS not found")
            return
        
        print(f"[*] Using parameters - Name: {name_param}, Message: {message_param}")
        
        # Test each XSS payload
        for payload_info in xss_payloads:
            payload_name = payload_info['name']
            payload_value = payload_info['payload']
            expected_result = payload_info['expected']
            xss_type = payload_info['type']
            vector = payload_info['vector']
            
            # Store payload for reporting
            self.tested_payloads.append({
                'name': payload_name,
                'payload': payload_value,
                'type': xss_type,
                'vector': vector,
                'category': 'Stored XSS'
            })
            
            try:
                print(f"  [*] Testing {payload_name}")
                
                # Respect delay between requests
                time.sleep(self.delay)
                
                # Get CSRF token for submission
                token = self.get_csrf_token(url)
                if not token:
                    print(f"  [-] Failed to get CSRF token for {payload_name}")
                    # Try without CSRF token - some DVWA levels don't require it
                    token = ''
                
                # Create data with payload
                data = {
                    name_param: 'Tester',
                    message_param: payload_value
                }
                
                # Add CSRF token if available
                if token:
                    data['user_token'] = token
                
                # Add submit button if exists
                submit_found = False
                for param in parameters:
                    if 'submit' in param['name'].lower() or 'sign' in param['name'].lower():
                        data[param['name']] = 'Sign Guestbook'
                        submit_found = True
                
                # If no submit button found, add a generic one
                if not submit_found:
                    data['btnSign'] = 'Sign Guestbook'
                
                print(f"  [*] Sending {method} request with data")
                
                # Send request to store the payload
                if method.upper() == 'GET':
                    response = self.session.get(url, params=data, verify=False, timeout=self.timeout)
                else:
                    response = self.session.post(url, data=data, verify=False, timeout=self.timeout)
                
                # Wait for incubation period
                print(f"  [*] Waiting {self.verification_delay}s for incubation...")
                time.sleep(self.verification_delay)
                
                # Verify if payload is stored and executed
                print(f"  [*] Verifying payload execution...")
                verify_response = self.session.get(url, verify=False, timeout=self.timeout)
                
                # Analyze response for payload execution
                result = {
                    'url': url,
                    'module': module,
                    'vuln_type': 'Stored XSS',
                    'name_parameter': name_param,
                    'message_parameter': message_param,
                    'payload_name': payload_name,
                    'payload': payload_value,
                    'vector': vector,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'vulnerable': False,
                    'description': '',
                    'response_preview': verify_response.text[:300] + '...' if len(verify_response.text) > 300 else verify_response.text,
                    'verification_delay': self.verification_delay
                }
                
                # Check for XSS execution
                response_lower = verify_response.text.lower()
                
                if expected_result.lower() in response_lower:
                    result['vulnerable'] = True
                    result['description'] = f"Found expected result: {expected_result}"
                
                # Additional checks for common XSS indicators
                xss_indicators = [
                    'alert(',
                    'onerror=',
                    'onload=',
                    'onclick=',
                    'javascript:',
                    '<script>',
                    '</script>',
                    'xss',
                    'incubated'
                ]
                
                for indicator in xss_indicators:
                    if indicator in verify_response.text.lower() and not result['vulnerable']:
                        result['vulnerable'] = True
                        result['description'] = f"Found XSS indicator: {indicator}"
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
                    'vuln_type': 'Stored XSS',
                    'name_parameter': name_param,
                    'message_parameter': message_param,
                    'payload_name': payload_name,
                    'payload': payload_value,
                    'vector': vector,
                    'status_code': 0,
                    'response_length': 0,
                    'vulnerable': False,
                    'description': f'Error: {str(e)}',
                    'error': True,
                    'verification_delay': self.verification_delay
                })
    
    def test_file_upload_incubated(self):
        """Test File Upload with Incubated Vulnerabilities"""
        print("[*] Testing File Upload Incubated Vulnerabilities...")
        
        # Find File Upload endpoint
        upload_endpoint = None
        for endpoint in self.endpoints:
            if 'upload' in endpoint['module']:
                upload_endpoint = endpoint
                break
        
        if not upload_endpoint:
            print("[-] File Upload endpoint not found")
            return
        
        url = upload_endpoint['url']
        parameters = upload_endpoint['parameters']
        module = upload_endpoint['module']
        method = upload_endpoint['method']
        
        print(f"[*] Testing File Upload on: {url}")
        print(f"[*] Available parameters: {[p['name'] for p in parameters]}")
        
        # Create malicious files for upload
        malicious_files = [
            {
                'name': 'HTML XSS File',
                'filename': 'test_xss.html',
                'content': '''<html>
<body>
<script>alert('INCUBATED-HTML-XSS')</script>
<h1>Test File</h1>
</body>
</html>''',
                'type': 'text/html',
                'expected': 'INCUBATED-HTML-XSS',
                'category': 'File Upload'
            }
        ]
        
        # Find file upload parameter
        file_param = None
        for param in parameters:
            param_name = param['name'].lower()
            if 'file' in param_name or 'upload' in param_name:
                file_param = param['name']
                break
        
        if not file_param:
            # Try to find any file input
            for param in parameters:
                if param.get('type') == 'file':
                    file_param = param['name']
                    break
        
        if not file_param:
            print("[-] File upload parameter not found")
            return
        
        print(f"[*] Using file parameter: {file_param}")
        
        # Test each malicious file
        for file_info in malicious_files:
            file_name = file_info['name']
            filename = file_info['filename']
            content = file_info['content']
            file_type = file_info['type']
            expected_result = file_info['expected']
            category = file_info['category']
            
            # Store payload for reporting
            self.tested_payloads.append({
                'name': file_name,
                'payload': f"File: {filename} with XSS content",
                'type': 'File Upload',
                'vector': file_type,
                'category': category
            })
            
            try:
                print(f"  [*] Testing {file_name}")
                
                # Respect delay between requests
                time.sleep(self.delay)
                
                # Get CSRF token for submission
                token = self.get_csrf_token(url)
                if not token:
                    print(f"  [-] Failed to get CSRF token for {file_name}")
                    # Try without CSRF token
                    token = ''
                
                # Create file-like object
                from io import BytesIO
                file_data = BytesIO(content.encode('utf-8'))
                
                # Create multipart form data
                files = {file_param: (filename, file_data, file_type)}
                data = {}
                
                # Add CSRF token if available
                if token:
                    data['user_token'] = token
                
                # Add other parameters if they exist
                submit_found = False
                for param in parameters:
                    if param['name'] not in [file_param] and ('submit' in param['name'].lower() or 'upload' in param['name'].lower()):
                        data[param['name']] = 'Upload'
                        submit_found = True
                
                # If no submit button found, add a generic one
                if not submit_found:
                    data['Upload'] = 'Upload'
                
                print(f"  [*] Uploading file: {filename}")
                
                # Send file upload request
                response = self.session.post(url, data=data, files=files, verify=False, timeout=self.timeout)
                
                # Wait for incubation period
                print(f"  [*] Waiting {self.verification_delay}s for incubation...")
                time.sleep(self.verification_delay)
                
                # Try to access the uploaded file (if URL is available)
                # This is a simplified check - in real scenarios, you'd need to parse the response
                # to find the uploaded file URL
                uploaded_file_url = urljoin(url, f"../../hackable/uploads/{filename}")
                print(f"  [*] Checking uploaded file at: {uploaded_file_url}")
                
                try:
                    file_response = self.session.get(uploaded_file_url, verify=False, timeout=self.timeout)
                    
                    # Analyze response for payload execution
                    result = {
                        'url': url,
                        'module': module,
                        'vuln_type': 'File Upload',
                        'parameter': file_param,
                        'payload_name': file_name,
                        'payload': f"File: {filename}",
                        'vector': file_type,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'vulnerable': False,
                        'description': '',
                        'response_preview': file_response.text[:300] + '...' if len(file_response.text) > 300 else file_response.text,
                        'verification_delay': self.verification_delay,
                        'uploaded_file_url': uploaded_file_url
                    }
                    
                    # Check for XSS execution in uploaded file
                    response_lower = file_response.text.lower()
                    
                    if expected_result.lower() in response_lower:
                        result['vulnerable'] = True
                        result['description'] = f"Found expected result in uploaded file: {expected_result}"
                    
                    # Additional checks for common XSS indicators
                    xss_indicators = [
                        'alert(',
                        'onload=',
                        'onerror=',
                        'xss',
                        'incubated'
                    ]
                    
                    for indicator in xss_indicators:
                        if indicator in response_lower and not result['vulnerable']:
                            result['vulnerable'] = True
                            result['description'] = f"Found XSS indicator in uploaded file: {indicator}"
                            break
                    
                    self.results.append(result)
                    
                    if result['vulnerable']:
                        print(f"  [+] VULNERABLE: {file_name} - {result['description']}")
                    else:
                        print(f"  [-] NOT VULNERABLE: {file_name}")
                        
                except Exception as file_access_error:
                    print(f"  [*] Could not access uploaded file: {file_access_error}")
                    # Still record the upload attempt
                    result = {
                        'url': url,
                        'module': module,
                        'vuln_type': 'File Upload',
                        'parameter': file_param,
                        'payload_name': file_name,
                        'payload': f"File: {filename}",
                        'vector': file_type,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'vulnerable': False,
                        'description': f'File upload completed, but could not verify execution: {str(file_access_error)}',
                        'response_preview': response.text[:300] + '...' if len(response.text) > 300 else response.text,
                        'verification_delay': self.verification_delay
                    }
                    self.results.append(result)
                    print(f"  [~] File uploaded but execution not verified: {file_name}")
                
            except Exception as e:
                print(f"  [-] Error testing {file_name}: {e}")
                self.results.append({
                    'url': url,
                    'module': module,
                    'vuln_type': 'File Upload',
                    'parameter': file_param,
                    'payload_name': file_name,
                    'payload': f"File: {filename}",
                    'vector': file_type,
                    'status_code': 0,
                    'response_length': 0,
                    'vulnerable': False,
                    'description': f'Error: {str(e)}',
                    'error': True,
                    'verification_delay': self.verification_delay
                })

    def generate_html_report(self):
        """Generate OWASP/OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        
        # Separate results by vulnerability type
        stored_xss_results = [r for r in self.results if r.get('vuln_type') == 'Stored XSS']
        file_upload_results = [r for r in self.results if r.get('vuln_type') == 'File Upload']
        
        stored_xss_vuln = sum(1 for r in stored_xss_results if r.get('vulnerable', False))
        file_upload_vuln = sum(1 for r in file_upload_results if r.get('vulnerable', False))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incubated Vulnerabilities Assessment - DVWA (OTG-INPVAL-015)</title>
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
        <h1>Incubated Vulnerabilities Assessment</h1>
        <p>DVWA Security Test - OWASP Testing Guide OTG-INPVAL-015</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-box">
            <p>This assessment identified <span class="risk-high">{vulnerable_count} Incubated Vulnerabilities</span> in the DVWA application. Incubated vulnerabilities are those that are stored or delayed in execution, manifesting their effects when the stored data is later processed or accessed. These vulnerabilities can be particularly dangerous as they may not be immediately apparent during initial testing.</p>
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
                <td>Incubated/Delayed Vulnerabilities</td>
            </tr>
            <tr>
                <td><strong>OWASP Test ID</strong></td>
                <td>OTG-INPVAL-015</td>
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
            <tr>
                <td><strong>Verification Delay</strong></td>
                <td>{self.verification_delay} seconds</td>
            </tr>
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Methodology</h2>
        <p>The testing methodology followed the OWASP Testing Guide for Incubated Vulnerabilities:</p>
        <ol>
            <li><strong>Authentication</strong>: Logged into DVWA with provided credentials</li>
            <li><strong>Endpoint Discovery</strong>: Identified modules that support stored/delayed processing</li>
            <li><strong>Incubated XSS Testing</strong>: Tested Stored XSS payloads in the Guestbook module</li>
            <li><strong>File Upload Testing</strong>: Tested malicious file uploads with delayed execution</li>
            <li><strong>Delayed Verification</strong>: Waited for incubation period and verified payload execution</li>
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
            if len(display_payload) > 50:
                display_payload = display_payload[:47] + "..."
            
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
                <h3>{stored_xss_vuln}</h3>
                <p>Stored XSS</p>
            </div>
            <div class="finding-item finding-vuln">
                <h3>{file_upload_vuln}</h3>
                <p>File Upload</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Detailed Findings</h2>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'storedxss')">Stored XSS</button>
            <button class="tablinks" onclick="openTab(event, 'fileupload')">File Upload</button>
        </div>

        <div id="storedxss" class="tabcontent" style="display:block">
            <h3>Stored XSS Results</h3>
            <p>The following Stored XSS tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>Vector</th>
                        <th>Payload Name</th>
                        <th>Delay (s)</th>
                        <th>Status</th>
                        <th>Status Code</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # Stored XSS results
        for result in stored_xss_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('module', 'Unknown'))}</td>
                        <td>{html.escape(result.get('vector', 'N/A'))}</td>
                        <td>{html.escape(result.get('payload_name', 'N/A'))}</td>
                        <td>{result.get('verification_delay', 'N/A')}</td>
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
            
            <h4>Stored XSS Vulnerabilities</h4>"""
        
        # Show only vulnerable Stored XSS results
        vulnerable_xss_results = [r for r in stored_xss_results if r.get('vulnerable', False)]
        
        if vulnerable_xss_results:
            for i, result in enumerate(vulnerable_xss_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
Vector: {html.escape(result.get('vector', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
Payload: {html.escape(result.get('payload', ''))}
Delay: {result.get('verification_delay', 'N/A')}s
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No Stored XSS vulnerabilities were found.</p>"""
        
        html_content += """
        </div>

        <div id="fileupload" class="tabcontent">
            <h3>File Upload Results</h3>
            <p>The following File Upload tests were conducted:</p>
            <table>
                <thead>
                    <tr>
                        <th>Module</th>
                        <th>File Type</th>
                        <th>Payload Name</th>
                        <th>Delay (s)</th>
                        <th>Status</th>
                        <th>Status Code</th>
                    </tr>
                </thead>
                <tbody>"""
        
        # File Upload results
        for result in file_upload_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "not-vulnerable"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            
            html_content += f"""
                    <tr>
                        <td>{html.escape(result.get('module', 'Unknown'))}</td>
                        <td>{html.escape(result.get('vector', 'N/A'))}</td>
                        <td>{html.escape(result.get('payload_name', 'N/A'))}</td>
                        <td>{result.get('verification_delay', 'N/A')}</td>
                        <td><span class="{status_class}">{status_text}</span></td>
                        <td>{result.get('status_code', 'N/A')}</td>
                    </tr>"""
            
            # Add description row if vulnerable
            if result.get('vulnerable', False):
                html_content += f"""
                    <tr>
                        <td colspan="6" style="background-color: #fff3e0;">
                            <strong>Description:</strong> {html.escape(result.get('description', ''))}<br>
                            <strong>File:</strong> {html.escape(result.get('payload', ''))}
                        </td>
                    </tr>"""
        
        html_content += f"""
                </tbody>
            </table>
            
            <h4>File Upload Vulnerabilities</h4>"""
        
        # Show only vulnerable File Upload results
        vulnerable_upload_results = [r for r in file_upload_results if r.get('vulnerable', False)]
        
        if vulnerable_upload_results:
            for i, result in enumerate(vulnerable_upload_results, 1):
                html_content += f"""
            <div class="code">
<strong>Vulnerability #{i}</strong>
Module: {html.escape(result.get('module', 'Unknown'))}
Endpoint: {html.escape(result.get('url', 'N/A'))}
File Type: {html.escape(result.get('vector', 'N/A'))}
Payload Name: {html.escape(result.get('payload_name', 'N/A'))}
File: {html.escape(result.get('payload', ''))}
Delay: {result.get('verification_delay', 'N/A')}s
Description: {html.escape(result.get('description', ''))}
Status Code: {result.get('status_code', 'N/A')}
Response Preview: {html.escape(result.get('response_preview', '')[:300])}
            </div>"""
        else:
            html_content += """
            <p>No File Upload vulnerabilities were found.</p>"""
        
        html_content += """
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Incubated Vulnerabilities Explained</h2>
        
        <h3>What are Incubated Vulnerabilities?</h3>
        <p>Incubated vulnerabilities are security flaws where the malicious payload is stored or delayed in execution, and the effects manifest when the stored data is later processed or accessed. Unlike immediate vulnerabilities, these require a "triggering" action to be exploited.</p>
        
        <h3>Common Types</h3>
        <ul>
            <li><strong>Stored XSS</strong>: Malicious scripts stored in databases or files that execute when viewed</li>
            <li><strong>Malicious File Uploads</strong>: Harmful files uploaded to servers that execute when accessed</li>
            <li><strong>Delayed Command Execution</strong>: Commands that execute when data is later processed</li>
            <li><strong>Log Poisoning</strong>: Malicious input that executes when logs are viewed</li>
        </ul>
        
        <h3>Detection Challenges</h3>
        <ul>
            <li><strong>Timing</strong>: Requires delayed verification to detect execution</li>
            <li><strong>Triggering</strong>: May require specific actions to activate the payload</li>
            <li><strong>Persistence</strong>: Payloads may persist across sessions</li>
            <li><strong>False Negatives</strong>: Immediate testing may miss delayed effects</li>
        </ul>
    </div>

    <div class="section">
        <h2 class="section-title">Remediation Recommendations</h2>
        <p>To prevent Incubated Vulnerabilities, implement the following measures:</p>
        
        <h3>Input Validation and Sanitization</h3>
        <ol>
            <li><strong>Whitelist Approach</strong>: Only allow known good input patterns</li>
            <li><strong>Content-Type Validation</strong>: Validate file types and content during upload</li>
            <li><strong>Size Limits</strong>: Restrict input and file sizes to prevent complex payloads</li>
            <li><strong>Character Encoding</strong>: Properly encode special characters</li>
        </ol>
        
        <h3>Output Encoding and Security</h3>
        <ol>
            <li><strong>Context-Aware Encoding</strong>: Encode data based on where it will be displayed</li>
            <li><strong>Content Security Policy</strong>: Implement strict CSP headers to prevent script execution</li>
            <li><strong>Secure File Storage</strong>: Store uploaded files outside web root or with restricted execution</li>
            <li><strong>Output Sanitization</strong>: Sanitize data before displaying it to users</li>
        </ol>
        
        <h3>Monitoring and Detection</h3>
        <ol>
            <li><strong>Regular Scanning</strong>: Periodically scan stored content for malicious payloads</li>
            <li><strong>Access Logging</strong>: Monitor access to uploaded files and stored content</li>
            <li><strong>Automated Detection</strong>: Implement automated tools to detect incubated vulnerabilities</li>
            <li><strong>Security Testing</strong>: Include delayed verification in security testing procedures</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_Incubated_Vulnerabilities">OWASP Testing Guide - OTG-INPVAL-015</a></li>
            <li><a href="https://owasp.org/www-community/attacks/xss/">OWASP Cross-Site Scripting (XSS)</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79: Cross-Site Scripting</a></li>
            <li><a href="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload">OWASP Unrestricted File Upload</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA) Documentation</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Generated by DVWA Incubated Vulnerabilities Testing Script | OWASP/OSCP-Style Report</p>
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
        print("=== DVWA Incubated Vulnerabilities Testing Script ===")
        print(f"Target: {self.base_url}")
        print(f"Output: {self.output_file}")
        print(f"Request delay: {self.delay}s")
        print(f"Verification delay: {self.verification_delay}s")
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
        
        # Test Stored XSS (Incubated)
        self.test_stored_xss()
        
        # Test File Upload Incubated Vulnerabilities
        self.test_file_upload_incubated()
        
        # Generate report
        self.generate_html_report()
        
        # Summary
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        stored_xss_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'Stored XSS' and r.get('vulnerable', False))
        file_upload_vuln = sum(1 for r in self.results if r.get('vuln_type') == 'File Upload' and r.get('vulnerable', False))
        
        total_tests = len(self.results)
        print(f"\n=== Test Summary ===")
        print(f"Total endpoints tested: {len(self.endpoints)}")
        print(f"Total tests conducted: {total_tests}")
        print(f"Stored XSS vulnerabilities: {stored_xss_vuln}")
        print(f"File Upload vulnerabilities: {file_upload_vuln}")
        print(f"Total vulnerabilities: {vulnerable_count}")
        print(f"Security status: {'VULNERABLE' if vulnerable_count > 0 else 'SECURE'}")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='DVWA Incubated Vulnerabilities Testing Script (OTG-INPVAL-015)')
    parser.add_argument('--url', default='http://localhost/dvwa', help='DVWA base URL (default: http://localhost/dvwa)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    parser.add_argument('--output', default='reports/incubated_vulnerabilities_report.html', help='Output HTML report file (default: reports/incubated_vulnerabilities_report.html)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--verification-delay', type=int, default=5, help='Delay for incubation verification in seconds (default: 5)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = DVWAIncubatedVulnerabilitiesTester(
        args.url, 
        args.username, 
        args.password, 
        args.output, 
        args.timeout, 
        args.delay,
        args.verification_delay
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