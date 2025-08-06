#!/usr/bin/env python3
"""
DVWA Test HTTP Methods (OTG-CONFIG-006)
Automated testing script for identifying HTTP method vulnerabilities
"""

import requests
import os
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from datetime import datetime
import argparse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWAHTTPMethodTester:
    def __init__(self, base_url="http://localhost"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'DVWA-HTTP-Tester/1.0'})
        self.findings = []
        
        # HTTP methods to test
        self.http_methods = [
            'GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 
            'TRACE', 'PATCH', 'CONNECT', 'PROPFIND', 'PROPPATCH',
            'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'
        ]
        
        # DVWA endpoints to test
        self.dvwa_endpoints = [
            '',
            'login.php',
            'index.php',
            'security.php',
            'logout.php',
            'setup.php',
            'instructions.php',
            'vulnerabilities/brute/',
            'vulnerabilities/exec/',
            'vulnerabilities/csrf/',
            'vulnerabilities/fi/',
            'vulnerabilities/upload/',
            'vulnerabilities/captcha/',
            'vulnerabilities/sqli/',
            'vulnerabilities/sqli_blind/',
            'vulnerabilities/weak_id/',
            'vulnerabilities/xss_r/',
            'vulnerabilities/xss_s/'
        ]

    def find_dvwa_path(self):
        """Try to find DVWA installation path"""
        possible_paths = [
            '/dvwa',
            '/DVWA',
            '/damn-vulnerable-web-application',
            ''
        ]
        
        for path in possible_paths:
            test_url = urljoin(self.base_url, path + '/login.php')
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200 and ('dvwa' in response.text.lower() or 'damn vulnerable' in response.text.lower()):
                    logger.info(f"Found DVWA at: {self.base_url}{path}")
                    return path
            except requests.exceptions.RequestException:
                continue
        
        return None

    def login(self, username="admin", password="password"):
        """Login to DVWA and handle CSRF token"""
        # Try to find DVWA path
        dvwa_path = self.find_dvwa_path()
        
        # If we can't find it automatically, try to infer from base_url
        if not dvwa_path:
            if '/dvwa' in self.base_url.lower():
                dvwa_path = '/dvwa'
            else:
                dvwa_path = ''
        
        # Construct the correct DVWA URL
        if dvwa_path:
            dvwa_url = urljoin(self.base_url + '/', dvwa_path.strip('/'))
        else:
            dvwa_url = self.base_url
            
        self.dvwa_url = dvwa_url
        
        try:
            logger.info(f"Attempting to login to DVWA at: {dvwa_url}")
            
            # Get login page to extract CSRF token
            login_url = urljoin(dvwa_url + '/', "login.php")
            logger.info(f"Fetching login page: {login_url}")
            
            response = self.session.get(login_url, timeout=10)
            
            if response.status_code != 200:
                logger.error(f"Failed to get login page: {response.status_code}")
                logger.error(f"Response URL: {response.url}")
                return False
            
            # Parse CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            user_token_elem = soup.find('input', {'name': 'user_token'})
            
            if not user_token_elem:
                logger.warning("CSRF token not found in login page, trying to login without it...")
                # Try without CSRF token
                login_data = {
                    'username': username,
                    'password': password,
                    'Login': 'Login'
                }
            else:
                user_token = user_token_elem.get('value')
                logger.info(f"Found CSRF token: {user_token[:20]}...")
                
                # Perform login
                login_data = {
                    'username': username,
                    'password': password,
                    'Login': 'Login',
                    'user_token': user_token
                }
            
            response = self.session.post(login_url, data=login_data, allow_redirects=True, timeout=10)
            
            # Check if login was successful
            if "Welcome to Damn Vulnerable Web Application" in response.text or "dvwa" in response.url.lower() or "/index.php" in response.url:
                logger.info("Successfully logged into DVWA")
                return True
            else:
                logger.error("Failed to login to DVWA")
                logger.error(f"Response URL: {response.url}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during login: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error during login: {str(e)}")
            return False

    def assess_method_risk(self, method, status_code, response_headers, response_text):
        """Assess risk level for HTTP method"""
        risk_level = 'Low'
        
        # High risk methods
        high_risk_methods = ['TRACE', 'PUT', 'DELETE', 'CONNECT']
        if method in high_risk_methods and status_code in [200, 201, 204]:
            risk_level = 'High'
        
        # Medium risk methods
        medium_risk_methods = ['PATCH', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']
        if method in medium_risk_methods and status_code in [200, 201, 204]:
            risk_level = 'Medium'
        
        # Check for TRACE response containing sensitive headers (XST)
        if method == 'TRACE' and status_code == 200:
            if 'authorization' in response_text.lower() or 'cookie' in response_text.lower():
                risk_level = 'High'
        
        # Check Allow/Public headers for dangerous methods
        allow_header = response_headers.get('allow', '')
        public_header = response_headers.get('public', '')
        combined_headers = (allow_header + public_header).upper()
        
        for dangerous_method in high_risk_methods:
            if dangerous_method in combined_headers:
                risk_level = 'High' if risk_level == 'Low' else risk_level
        
        return risk_level

    def test_http_method(self, url, method):
        """Test a specific HTTP method on a URL"""
        try:
            logger.info(f"Testing {method} on {url}")
            
            # Prepare request data
            headers = {'X-Testing-Method': method}
            data = None
            
            # Add data for methods that typically require it
            if method in ['POST', 'PUT', 'PATCH']:
                data = {'test': 'data'}
            
            # Send request using the specific method
            response = self.session.request(method, url, headers=headers, data=data, timeout=10)
            
            # Get allowed methods from headers
            allow_header = response.headers.get('allow', '')
            public_header = response.headers.get('public', '')
            
            result = {
                'url': url,
                'method': method,
                'status_code': response.status_code,
                'response_headers': dict(response.headers),
                'allow_header': allow_header,
                'public_header': public_header,
                'content_length': len(response.content),
                'successful': response.status_code in [200, 201, 204],
                'risk_level': self.assess_method_risk(method, response.status_code, response.headers, response.text),
                'description': f'{method} method test'
            }
            
            # Additional analysis for OPTIONS request
            if method == 'OPTIONS':
                if allow_header or public_header:
                    result['description'] = f'OPTIONS response shows allowed methods: {allow_header or public_header}'
                    # Check if dangerous methods are allowed
                    combined = (allow_header + public_header).upper()
                    if any(dangerous in combined for dangerous in ['TRACE', 'PUT', 'DELETE', 'CONNECT']):
                        result['risk_level'] = 'High'
                    elif any(dangerous in combined for dangerous in ['PATCH', 'PROPFIND']):
                        result['risk_level'] = 'Medium'
            
            # Additional analysis for TRACE request
            if method == 'TRACE' and response.status_code == 200:
                if 'authorization' in response.text.lower() or 'cookie' in response.text.lower():
                    result['description'] = 'TRACE method enabled with sensitive header reflection (XST vulnerability)'
                    result['risk_level'] = 'High'
                else:
                    result['description'] = 'TRACE method enabled (potential XST vulnerability)'
                    result['risk_level'] = 'Medium'
            
            self.findings.append(result)
            return result
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for {method} {url}: {str(e)}")
            return {
                'url': url,
                'method': method,
                'status_code': 0,
                'response_headers': {},
                'allow_header': '',
                'public_header': '',
                'content_length': 0,
                'successful': False,
                'risk_level': 'Low',
                'error': str(e),
                'description': f'{method} method test failed'
            }

    def test_method_tampering(self, url):
        """Test HTTP method tampering"""
        try:
            logger.info(f"Testing method tampering on {url}")
            
            # Test sending POST data with GET method
            response_get = self.session.get(url, data={'test': 'data'}, timeout=10)
            if response_get.status_code == 200:
                result_get = {
                    'url': url,
                    'method': 'GET with POST data',
                    'status_code': response_get.status_code,
                    'response_headers': dict(response_get.headers),
                    'allow_header': '',
                    'public_header': '',
                    'content_length': len(response_get.content),
                    'successful': True,
                    'risk_level': 'Medium' if 'test' in response_get.text else 'Low',
                    'description': 'GET method accepting POST data (method tampering)'
                }
                self.findings.append(result_get)
            
            # Test sending GET data with POST method
            response_post = self.session.post(url, params={'test': 'param'}, timeout=10)
            if response_post.status_code == 200:
                result_post = {
                    'url': url,
                    'method': 'POST with GET params',
                    'status_code': response_post.status_code,
                    'response_headers': dict(response_post.headers),
                    'allow_header': '',
                    'public_header': '',
                    'content_length': len(response_post.content),
                    'successful': True,
                    'risk_level': 'Medium' if 'test' in response_post.text else 'Low',
                    'description': 'POST method accepting GET parameters (method tampering)'
                }
                self.findings.append(result_post)
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Method tampering test failed for {url}: {str(e)}")

    def run_tests(self):
        """Run all HTTP method tests"""
        logger.info("Starting HTTP method testing...")
        logger.info(f"DVWA URL: {self.dvwa_url}")
        
        tested_combinations = set()
        total_tests = 0
        high_risk_findings = 0
        
        # Test each endpoint with each method
        for endpoint in self.dvwa_endpoints:
            # Construct full URL
            full_url = urljoin(self.dvwa_url + '/', endpoint)
            
            for method in self.http_methods:
                # Avoid duplicate tests
                test_key = (full_url, method)
                if test_key in tested_combinations:
                    continue
                    
                tested_combinations.add(test_key)
                
                result = self.test_http_method(full_url, method)
                total_tests += 1
                
                if result['risk_level'] in ['High', 'Medium']:
                    high_risk_findings += 1
                    logger.info(f"Found {result['risk_level']} risk: {method} method on {full_url}")
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.05)
        
        # Test method tampering on key endpoints
        key_endpoints = ['', 'login.php', 'vulnerabilities/upload/']
        for endpoint in key_endpoints:
            full_url = urljoin(self.dvwa_url + '/', endpoint)
            self.test_method_tampering(full_url)
        
        logger.info(f"Completed testing. Found {high_risk_findings} high/medium risk issues out of {total_tests} tests.")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Sort findings by risk level
        high_risk = [f for f in self.findings if f.get('risk_level') == 'High']
        medium_risk = [f for f in self.findings if f.get('risk_level') == 'Medium']
        low_risk = [f for f in self.findings if f.get('risk_level') == 'Low']
        
        # Generate HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DVWA HTTP Methods Test Report</title>
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
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .section {{
            background: white;
            margin-bottom: 30px;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .finding {{
            border: 1px solid #ddd;
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
            background-color: #fafafa;
        }}
        .risk-high {{
            border-left: 5px solid #e74c3c;
            background-color: #fdf2f2;
        }}
        .risk-medium {{
            border-left: 5px solid #f39c12;
            background-color: #fff9f2;
        }}
        .risk-low {{
            border-left: 5px solid #27ae60;
            background-color: #f2fdf5;
        }}
        .risk-tag {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .risk-high-tag {{
            background-color: #e74c3c;
            color: white;
        }}
        .risk-medium-tag {{
            background-color: #f39c12;
            color: white;
        }}
        .risk-low-tag {{
            background-color: #27ae60;
            color: white;
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
            background-color: #34495e;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .code-block {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .summary-stats {{
            display: flex;
            justify-content: space-around;
            text-align: center;
            margin: 20px 0;
        }}
        .stat-box {{
            padding: 20px;
            border-radius: 8px;
            color: white;
            font-weight: bold;
        }}
        .high-stat {{
            background-color: #e74c3c;
        }}
        .medium-stat {{
            background-color: #f39c12;
        }}
        .low-stat {{
            background-color: #27ae60;
        }}
        .total-stat {{
            background-color: #3498db;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .note {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 0 4px 4px 0;
        }}
        .warning {{
            background-color: #f8d7da;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin: 20px 0;
            border-radius: 0 4px 4px 0;
        }}
        .success {{
            background-color: #d4edda;
            border-left: 4px solid #27ae60;
            padding: 15px;
            margin: 20px 0;
            border-radius: 0 4px 4px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DVWA Security Test Report</h1>
        <p>Test HTTP Methods (OTG-CONFIG-006)</p>
        <p>Generated on: {timestamp}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report presents the findings of a security assessment focused on testing HTTP methods for the Damn Vulnerable Web Application (DVWA). The test was conducted according to OWASP Testing Guide v4 methodology OTG-CONFIG-006.</p>
        
        <div class="summary-stats">
            <div class="stat-box total-stat">
                <div class="stat-number">{len(self.findings)}</div>
                <div>Total Tests Performed</div>
            </div>
            <div class="stat-box high-stat">
                <div class="stat-number">{len(high_risk)}</div>
                <div>High Risk Issues</div>
            </div>
            <div class="stat-box medium-stat">
                <div class="stat-number">{len(medium_risk)}</div>
                <div>Medium Risk Issues</div>
            </div>
        </div>"""
        
        if len(high_risk) > 0:
            html_content += """
        <div class="warning">
            <strong>Security Alert:</strong> High-risk HTTP method vulnerabilities were found. These should be reviewed and secured immediately.
        </div>"""
        elif len(medium_risk) > 0:
            html_content += """
        <div class="note">
            <strong>Security Notice:</strong> Medium-risk HTTP method issues were found. These should be reviewed for proper configuration.
        </div>"""
        else:
            html_content += """
        <div class="success">
            <strong>Good Security Posture:</strong> No high-risk HTTP method vulnerabilities were found during this test.
        </div>"""
        
        html_content += f"""
    </div>

    <div class="section">
        <h2>Test Overview</h2>
        <h3>OWASP Testing Guide - OTG-CONFIG-006</h3>
        <p><strong>Objective:</strong> Test HTTP Methods</p>
        <p><strong>Description:</strong> Verify that the web server and application properly handle HTTP methods and do not expose dangerous methods that could be exploited.</p>
        <p><strong>Target:</strong> {self.dvwa_url}</p>
        <p><strong>Methods Tested:</strong> {len(self.http_methods)} HTTP methods</p>
        <p><strong>Endpoints Tested:</strong> {len(self.dvwa_endpoints)} DVWA endpoints</p>
        <p><strong>Total Tests Performed:</strong> {len(self.findings)}</p>
    </div>

    <div class="section">
        <h2>Methodology</h2>
        <p>The testing methodology included the following steps:</p>
        <ol>
            <li><strong>Authentication:</strong> Logged into DVWA with default credentials</li>
            <li><strong>Method Enumeration:</strong> Tested {len(self.http_methods)} HTTP methods including:
                <ul>
                    <li>Standard methods: GET, POST, HEAD, OPTIONS</li>
                    <li>Extended methods: PUT, DELETE, TRACE, PATCH, CONNECT</li>
                    <li>WebDAV methods: PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK</li>
                </ul>
            </li>
            <li><strong>Endpoint Testing:</strong> Tested methods on {len(self.dvwa_endpoints)} key DVWA endpoints including:
                <ul>
                    <li>Main application pages</li>
                    <li>Authentication interfaces</li>
                    <li>Security configuration pages</li>
                    <li>Vulnerability modules</li>
                </ul>
            </li>
            <li><strong>Method Tampering:</strong> Tested HTTP method bypass techniques</li>
            <li><strong>Risk Assessment:</strong> Analyzed responses for security implications</li>
        </ol>
    </div>"""

        if self.findings:
            html_content += """
    <div class="section">
        <h2>Findings Summary</h2>
        <table>
            <tr>
                <th>Endpoint</th>
                <th>Method</th>
                <th>Status Code</th>
                <th>Risk Level</th>
            </tr>"""
            
            # Sort findings: High risk first, then Medium, then Low
            sorted_findings = sorted(self.findings, key=lambda x: (
                0 if x.get('risk_level') == 'High' else
                1 if x.get('risk_level') == 'Medium' else
                2
            ))
            
            # Add findings to table (limit to first 50 for readability)
            for finding in sorted_findings[:50]:
                risk_class = finding.get('risk_level', 'Low').lower()
                endpoint_path = finding['url'].replace(self.dvwa_url, '')
                
                html_content += f"""
            <tr>
                <td>{endpoint_path}</td>
                <td>{finding['method']}</td>
                <td>{finding['status_code']}</td>
                <td><span class="risk-tag risk-{risk_class}-tag">{finding.get('risk_level', 'Low')}</span></td>
            </tr>"""
            
            if len(sorted_findings) > 50:
                html_content += f"""
            <tr>
                <td colspan="4" style="text-align: center;"><em>... and {len(sorted_findings) - 50} more findings</em></td>
            </tr>"""
            
            html_content += """
        </table>
    </div>"""

            # Add detailed findings only for High/Medium risk
            significant_findings = [f for f in self.findings if f.get('risk_level') in ['High', 'Medium']]
            if significant_findings:
                html_content += """
    <div class="section">
        <h2>Detailed Findings (High/Medium Risk)</h2>"""
                
                # Sort by risk level
                sorted_significant = sorted(significant_findings, key=lambda x: (
                    0 if x.get('risk_level') == 'High' else 1
                ))
                
                # Add detailed findings
                for finding in sorted_significant:
                    risk_class = finding.get('risk_level', 'Low').lower()
                    endpoint_path = finding['url'].replace(self.dvwa_url, '')
                    
                    html_content += f"""
        <div class="finding risk-{risk_class}">
            <h3>{endpoint_path} - {finding['method']}</h3>
            <p><strong>Risk Level:</strong> <span class="risk-tag risk-{risk_class}-tag">{finding.get('risk_level', 'Low')}</span></p>
            <p><strong>HTTP Status:</strong> {finding['status_code']}</p>
            <p><strong>Content Length:</strong> {finding['content_length']} bytes</p>"""
                    
                    if finding.get('description'):
                        html_content += f"""
            <p><strong>Description:</strong> {finding.get('description')}</p>"""
                    
                    if finding.get('allow_header'):
                        html_content += f"""
            <p><strong>Allow Header:</strong> {finding['allow_header']}</p>"""
                    
                    if finding.get('public_header'):
                        html_content += f"""
            <p><strong>Public Header:</strong> {finding['public_header']}</p>"""
                    
                    html_content += f"""
            <p><strong>URL:</strong> <a href="{finding['url']}" target="_blank">{finding['url']}</a></p>
        </div>"""
                
                html_content += """
    </div>"""
        else:
            html_content += """
    <div class="section">
        <h2>Findings Summary</h2>
        <div class="success">
            <strong>Good News:</strong> No HTTP method vulnerabilities were found during this test.
        </div>
    </div>"""

        html_content += """
    <div class="section">
        <h2>HTTP Methods Overview</h2>
        <h3>Standard HTTP Methods</h3>
        <ul>
            <li><strong>GET</strong> - Retrieve information (Generally safe)</li>
            <li><strong>POST</strong> - Submit data (Generally safe)</li>
            <li><strong>HEAD</strong> - Retrieve headers only (Generally safe)</li>
            <li><strong>OPTIONS</strong> - Query available methods (Informational)</li>
        </ul>
        
        <h3>Dangerous HTTP Methods</h3>
        <ul>
            <li><strong>TRACE</strong> - Echoes back the received request (High risk - XST vulnerability)</li>
            <li><strong>PUT</strong> - Upload file/resource (High risk)</li>
            <li><strong>DELETE</strong> - Delete resource (High risk)</li>
            <li><strong>CONNECT</strong> - Reserved for proxies (High risk)</li>
            <li><strong>PATCH</strong> - Partial resource modification (Medium risk)</li>
        </ul>
        
        <h3>WebDAV Methods</h3>
        <ul>
            <li><strong>PROPFIND</strong> - Retrieve properties (Medium risk)</li>
            <li><strong>PROPPATCH</strong> - Modify properties (Medium risk)</li>
            <li><strong>MKCOL</strong> - Create collection/directory (Medium risk)</li>
            <li><strong>COPY/MOVE</strong> - File operations (Medium risk)</li>
            <li><strong>LOCK/UNLOCK</strong> - Resource locking (Medium risk)</li>
        </ul>
    </div>

    <div class="section">
        <h2>Remediation Recommendations</h2>
        <ol>
            <li><strong>Disable Dangerous Methods:</strong> Explicitly disable HTTP methods that are not required for application functionality</li>
            <li><strong>Web Server Configuration:</strong> Configure web server to reject dangerous HTTP methods</li>
            <li><strong>Application-Level Controls:</strong> Implement proper method validation in the application</li>
            <li><strong>Regular Auditing:</strong> Periodically test HTTP methods to ensure they remain properly restricted</li>
            <li><strong>Security Headers:</strong> Implement proper security headers to prevent method abuse</li>
        </ol>
        <h3>Apache Configuration Example:</h3>
        <div class="code-block">
# Disable dangerous HTTP methods<br>
<LimitExcept GET POST HEAD OPTIONS><br>
    Require all denied<br>
</LimitExcept><br><br>
# Explicitly deny TRACE method<br>
TraceEnable Off
        </div>
        <h3>Nginx Configuration Example:</h3>
        <div class="code-block">
# Block dangerous HTTP methods<br>
if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$ ) {{<br>
    return 405;<br>
}}<br><br>
# Disable TRACE method<br>
more_clear_headers ' TRACE';
        </div>
    </div>

    <div class="section">
        <h2>Conclusion</h2>
        <p>The HTTP method assessment evaluated the web application's handling of various HTTP methods to identify potential security vulnerabilities. """
        
        if len(high_risk) > 0:
            html_content += f"""The assessment identified {len(high_risk)} high-risk HTTP method vulnerabilities that require immediate attention to prevent potential exploitation."""
        elif len(medium_risk) > 0:
            html_content += f"""The assessment found {len(medium_risk)} medium-risk HTTP method issues that should be reviewed for proper configuration."""
        elif len(self.findings) > 0:
            html_content += f"""The assessment tested {len(self.findings)} HTTP method combinations, but none posed high security risks. This indicates reasonable HTTP method handling."""
        else:
            html_content += "The assessment found no HTTP method vulnerabilities, indicating good security practices for HTTP method handling."
        
        html_content += """</p>
        <p>This assessment demonstrates the importance of proper HTTP method validation and restriction. Organizations should ensure that only necessary HTTP methods are enabled and that dangerous methods like TRACE, PUT, and DELETE are properly disabled to prevent potential exploitation.</p>
    </div>

    <div class="footer">
        <p>Generated by DVWA HTTP Methods Test Script | OTG-CONFIG-006</p>
        <p>This is a security testing report for educational purposes</p>
    </div>
</body>
</html>"""
        
        # Save report
        os.makedirs('reports', exist_ok=True)
        report_path = 'reports/DVWA_HTTP_Methods_Report.html'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Report generated: {report_path}")
        return report_path

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='DVWA Test HTTP Methods (OTG-CONFIG-006)')
    parser.add_argument('--url', default='http://localhost', help='Base URL of the web server (default: http://localhost)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    
    args = parser.parse_args()
    
    print("[+] DVWA Test HTTP Methods (OTG-CONFIG-006)")
    print(f"[+] Target URL: {args.url}")
    print("[+] Starting security assessment...")
    
    # Initialize tester
    tester = DVWAHTTPMethodTester(base_url=args.url)
    
    # Login to DVWA
    if not tester.login(username=args.username, password=args.password):
        print("[-] Failed to login to DVWA. Please ensure:")
        print("    1. XAMPP is running")
        print("    2. DVWA is installed and accessible")
        print("    3. Credentials are correct")
        print("    4. DVWA security level is set to 'Low'")
        print("    5. Try specifying the full DVWA URL, e.g., --url http://localhost/dvwa")
        return 1
    
    # Run tests
    tester.run_tests()
    
    # Generate report
    report_path = tester.generate_html_report()
    
    print(f"[+] Testing completed successfully!")
    print(f"[+] Report generated: {report_path}")
    print("[+] Open the HTML report in a browser to view detailed findings")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())