#!/usr/bin/env python3
"""
DVWA Enumerate Infrastructure and Application Admin Interfaces (OTG-CONFIG-005)
Automated testing script for identifying administrative interfaces
"""

import requests
import os
import time
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from datetime import datetime
import argparse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWAAdminInterfaceTester:
    def __init__(self, base_url="http://localhost"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'DVWA-Admin-Tester/1.0'})
        self.findings = []
        
        # Common admin interface paths
        self.admin_paths = [
            # Application Admin Interfaces
            'admin/', 'administrator/', 'admincp/', 'controlpanel/', 'cp/',
            'adminarea/', 'admincontrol/', 'adminpanel/', 'admins/',
            'siteadmin/', 'webadmin/', 'sysadmin/', 'admin1/', 'admin2/',
            'admin_login/', 'admin-login/', 'login/admin/', 'admin/home',
            
            # CMS/Admin Frameworks
            'wp-admin/', 'wp-login.php', 'user/login/', 'login.php',
            'manager/', 'modx/manager/', 'admin-console/',
            
            # Database Admin Interfaces
            'phpmyadmin/', 'phpMyAdmin/', 'pma/', 'mysql/', 'db/', 'database/',
            'phpsqliteadmin/', 'phpPgAdmin/', 'adminer/', 'myadmin/',
            
            # Server Infrastructure
            'server-status', 'server-info', 'phpinfo.php', 'info.php',
            'xampp/', 'xampp/status.php', 'xampp/security.php',
            'webalizer/', 'stats/', 'status/', 'nagios/', 'cacti/',
            
            # Configuration/Setup
            'config/', 'configuration/', 'setup/', 'install/', 'install.php',
            'install/index.php', 'installer/', 'upgrade.php',
            
            # Development/Debug
            'debug/', 'test/', 'testing/', 'dev/', 'development/',
            'backup/', 'backups/', 'logs/', 'log/', 'tmp/', 'temp/',
            
            # Common Files
            'robots.txt', 'sitemap.xml', 'config.php', '.env',
            'web.config', '.htaccess', 'README.md', 'readme.txt'
        ]
        
        # DVWA-specific administrative interfaces
        self.dvwa_admin_paths = [
            'vulnerabilities/authbypass/',
            'vulnerabilities/csrf/',
            'setup.php',
        ]
        
        # Interface types for categorization
        self.interface_types = {
            'Application Admin': ['admin', 'administrator', 'admincp', 'controlpanel', 'cp', 'adminarea', 'wp-admin'],
            'Database Admin': ['phpmyadmin', 'mysql', 'db', 'database', 'phpsqliteadmin', 'phpPgAdmin', 'adminer'],
            'Server Infrastructure': ['server-status', 'server-info', 'phpinfo', 'xampp', 'webalizer', 'status'],
            'Configuration': ['config', 'setup', 'install', 'upgrade'],
            'Development': ['debug', 'test', 'dev', 'backup', 'logs'],
            'DVWA Vulnerabilities': ['vulnerabilities', 'dvwa'],
            'DVWA Admin': ['setup', 'instructions', 'phpinfo']
        }

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

    def test_dvwa_auth_bypass(self):
        """Test DVWA authentication bypass vulnerability specifically"""
        try:
            # Use the correct DVWA URL for auth bypass
            auth_bypass_url = urljoin(self.dvwa_url + '/', 'vulnerabilities/authbypass/')
            logger.info(f"Testing DVWA Auth Bypass: {auth_bypass_url}")
            
            # Test without credentials first
            response = self.session.get(auth_bypass_url, timeout=10)
            
            result = {
                'url': auth_bypass_url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', 'unknown'),
                'accessible': response.status_code == 200,
                'interface_type': 'DVWA Vulnerabilities',
                'risk_level': 'High' if response.status_code == 200 else 'Medium',
                'tested_at': 'dvwa_vulnerabilities',
                'description': 'DVWA Authentication Bypass Vulnerability'
            }
            
            self.findings.append(result)
            
            # If accessible, test with default credentials
            if response.status_code == 200:
                logger.info("Auth bypass interface accessible, testing user access...")
                
                # Test GordonB user access (if form is present)
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.find('form') or 'login' in response.text.lower():
                    # Try to access with GordonB credentials
                    login_data = {'username': 'gordonb', 'password': 'abc123'}
                    login_response = self.session.post(auth_bypass_url, data=login_data, timeout=10)
                    
                    login_result = {
                        'url': auth_bypass_url + " (with gordonb:abc123)",
                        'status_code': login_response.status_code,
                        'content_length': len(login_response.content),
                        'content_type': login_response.headers.get('content-type', 'unknown'),
                        'accessible': login_response.status_code == 200,
                        'interface_type': 'DVWA Vulnerabilities',
                        'risk_level': 'High',
                        'tested_at': 'dvwa_vulnerabilities',
                        'description': 'DVWA Authentication Bypass with Default Credentials'
                    }
                    
                    self.findings.append(login_result)
            
            return result
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for auth bypass test: {str(e)}")
            return {
                'url': urljoin(self.dvwa_url + '/', 'vulnerabilities/authbypass/'),
                'status_code': 0,
                'content_length': 0,
                'content_type': 'error',
                'accessible': False,
                'interface_type': 'DVWA Vulnerabilities',
                'risk_level': 'Low',
                'error': str(e),
                'tested_at': 'dvwa_vulnerabilities'
            }

    def categorize_interface(self, path):
        """Categorize the interface type based on path"""
        path_lower = path.lower()
        
        for category, keywords in self.interface_types.items():
            for keyword in keywords:
                if keyword in path_lower:
                    return category
        
        return 'Unknown'

    def assess_risk_level(self, status_code, content, path):
        """Assess risk level based on response"""
        risk_level = 'Low'
        
        # High risk indicators
        if status_code == 200:
            content_lower = content.lower()
            
            # Login/Authentication pages
            if any(indicator in content_lower for indicator in [
                'login', 'username', 'password', 'authenticate', 'signin'
            ]):
                risk_level = 'Medium'
            
            # Administrative functionality
            if any(indicator in content_lower for indicator in [
                'admin', 'control panel', 'dashboard', 'configuration',
                'settings', 'manage', 'database', 'server'
            ]):
                risk_level = 'High'
            
            # Debug/information disclosure
            if any(indicator in content_lower for indicator in [
                'phpinfo', 'server-status', 'debug', 'version'
            ]):
                risk_level = 'High'
                
            # DVWA vulnerabilities
            if 'dvwa' in path.lower() and 'vulnerabilities' in path.lower():
                risk_level = 'High'
        
        # Medium risk for redirect responses
        elif status_code in [301, 302, 307, 308]:
            risk_level = 'Medium'
            
        # Low risk for not found or forbidden
        elif status_code in [403, 404]:
            risk_level = 'Low'
        
        return risk_level

    def test_admin_interface(self, path):
        """Test access to an admin interface"""
        try:
            # Test relative to DVWA root
            dvwa_full_url = urljoin(self.dvwa_url + '/', path)
            logger.info(f"Testing DVWA interface: {dvwa_full_url}")
            
            response = self.session.get(dvwa_full_url, timeout=10)
            
            result = {
                'url': dvwa_full_url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', 'unknown'),
                'accessible': response.status_code in [200, 301, 302, 307, 308],
                'redirect_url': response.headers.get('location', '') if response.status_code in [301, 302, 307, 308] else '',
                'interface_type': self.categorize_interface(path),
                'risk_level': self.assess_risk_level(response.status_code, response.text, path),
                'tested_at': 'dvwa_root'
            }
            
            if response.status_code == 200:
                # Check for specific content indicators
                content_lower = response.text.lower()
                if 'phpmyadmin' in content_lower:
                    result['interface_type'] = 'Database Admin'
                    result['risk_level'] = 'High'
                elif 'phpinfo' in content_lower:
                    result['interface_type'] = 'Server Infrastructure'
                    result['risk_level'] = 'High'
                elif 'xampp' in content_lower:
                    result['interface_type'] = 'Server Infrastructure'
                    result['risk_level'] = 'Medium'
                elif 'dvwa' in content_lower and 'vulnerabilities' in content_lower:
                    result['interface_type'] = 'DVWA Vulnerabilities'
                    result['risk_level'] = 'High'
            
            self.findings.append(result)
            
            # Also test relative to server root (if different from DVWA root)
            if self.dvwa_url != self.base_url:
                server_full_url = urljoin(self.base_url + '/', path)
                if server_full_url != dvwa_full_url:  # Avoid duplicate testing
                    logger.info(f"Testing server interface: {server_full_url}")
                    
                    response2 = self.session.get(server_full_url, timeout=10)
                    
                    result2 = {
                        'url': server_full_url,
                        'status_code': response2.status_code,
                        'content_length': len(response2.content),
                        'content_type': response2.headers.get('content-type', 'unknown'),
                        'accessible': response2.status_code in [200, 301, 302, 307, 308],
                        'redirect_url': response2.headers.get('location', '') if response2.status_code in [301, 302, 307, 308] else '',
                        'interface_type': self.categorize_interface(path),
                        'risk_level': self.assess_risk_level(response2.status_code, response2.text, path),
                        'tested_at': 'server_root'
                    }
                    
                    self.findings.append(result2)
            
            return result
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for {path}: {str(e)}")
            return {
                'url': urljoin(self.dvwa_url + '/', path),
                'status_code': 0,
                'content_length': 0,
                'content_type': 'error',
                'accessible': False,
                'interface_type': self.categorize_interface(path),
                'risk_level': 'Low',
                'error': str(e),
                'tested_at': 'dvwa_root'
            }

    def run_tests(self):
        """Run all admin interface tests"""
        logger.info("Starting admin interface enumeration tests...")
        logger.info(f"DVWA URL: {self.dvwa_url}")
        logger.info(f"Server URL: {self.base_url}")
        
        tested_paths = set()
        accessible_interfaces = 0
        high_risk_interfaces = 0
        
        # Test DVWA-specific interfaces first
        logger.info("Testing DVWA-specific administrative interfaces...")
        for path in self.dvwa_admin_paths:
            normalized_path = path.rstrip('/') + '/' if path.endswith('/') or '.' not in path.split('/')[-1] else path
            
            if normalized_path in tested_paths:
                continue
                
            tested_paths.add(normalized_path)
            
            result = self.test_admin_interface(normalized_path)
            
            if result['accessible']:
                accessible_interfaces += 1
                if result['risk_level'] == 'High':
                    high_risk_interfaces += 1
                    logger.info(f"Found high-risk DVWA interface: {normalized_path} (Type: {result['interface_type']})")
                elif result['risk_level'] == 'Medium':
                    logger.info(f"Found medium-risk DVWA interface: {normalized_path} (Type: {result['interface_type']})")
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
        
        # Test common admin paths
        logger.info("Testing common administrative interface paths...")
        for path in self.admin_paths:
            normalized_path = path.rstrip('/') + '/' if path.endswith('/') or '.' not in path.split('/')[-1] else path
            
            if normalized_path in tested_paths:
                continue
                
            tested_paths.add(normalized_path)
            
            result = self.test_admin_interface(normalized_path)
            
            if result['accessible']:
                accessible_interfaces += 1
                if result['risk_level'] == 'High':
                    high_risk_interfaces += 1
                    logger.info(f"Found high-risk interface: {normalized_path} (Type: {result['interface_type']})")
                elif result['risk_level'] == 'Medium':
                    logger.info(f"Found medium-risk interface: {normalized_path} (Type: {result['interface_type']})")
            
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
        
        # Test specific DVWA auth bypass
        logger.info("Testing DVWA authentication bypass vulnerability...")
        auth_result = self.test_dvwa_auth_bypass()
        if auth_result['accessible']:
            accessible_interfaces += 1
            if auth_result['risk_level'] == 'High':
                high_risk_interfaces += 1
                logger.info("Found accessible DVWA authentication bypass interface")
        
        logger.info(f"Completed testing. Found {accessible_interfaces} accessible interfaces ({high_risk_interfaces} high-risk) out of {len(tested_paths) + 1} tested.")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Sort findings by risk level and accessibility
        accessible_findings = [f for f in self.findings if f.get('accessible', False)]
        inaccessible_findings = [f for f in self.findings if not f.get('accessible', False)]
        
        # Sort accessible findings by risk level
        high_risk = [f for f in accessible_findings if f.get('risk_level') == 'High']
        medium_risk = [f for f in accessible_findings if f.get('risk_level') == 'Medium']
        low_risk = [f for f in accessible_findings if f.get('risk_level') == 'Low']
        
        # Generate HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DVWA Admin Interfaces Test Report</title>
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
        .interface-type-tag {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.9em;
            margin-left: 10px;
            background-color: #3498db;
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
        <p>Enumerate Infrastructure and Application Admin Interfaces (OTG-CONFIG-005)</p>
        <p>Generated on: {timestamp}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report presents the findings of a security assessment focused on identifying administrative interfaces and infrastructure management endpoints in the Damn Vulnerable Web Application (DVWA). The test was conducted according to OWASP Testing Guide v4 methodology OTG-CONFIG-005.</p>
        
        <div class="summary-stats">
            <div class="stat-box total-stat">
                <div class="stat-number">{len(accessible_findings)}</div>
                <div>Accessible Interfaces</div>
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
            <strong>Security Alert:</strong> High-risk administrative interfaces were found accessible. These should be reviewed and secured immediately.
        </div>"""
        elif len(medium_risk) > 0:
            html_content += """
        <div class="note">
            <strong>Security Notice:</strong> Medium-risk administrative interfaces were found. These should be reviewed for proper access controls.
        </div>"""
        else:
            html_content += """
        <div class="success">
            <strong>Good Security Posture:</strong> No high-risk administrative interfaces were found during this test.
        </div>"""
        
        html_content += f"""
    </div>

    <div class="section">
        <h2>Test Overview</h2>
        <h3>OWASP Testing Guide - OTG-CONFIG-005</h3>
        <p><strong>Objective:</strong> Enumerate Infrastructure and Application Admin Interfaces</p>
        <p><strong>Description:</strong> Identify administrative interfaces, configuration panels, and infrastructure management endpoints that may provide elevated access or sensitive information.</p>
        <p><strong>Target:</strong> {self.dvwa_url}</p>
        <p><strong>Server Root:</strong> {self.base_url}</p>
        <p><strong>Paths Tested:</strong> {len(self.admin_paths) + len(self.dvwa_admin_paths) + 1} administrative interface paths</p>
        <p><strong>Accessible Interfaces Found:</strong> {len(accessible_findings)}</p>
    </div>

    <div class="section">
        <h2>Methodology</h2>
        <p>The testing methodology included the following steps:</p>
        <ol>
            <li><strong>Authentication:</strong> Logged into DVWA with default credentials</li>
            <li><strong>Path Enumeration:</strong> Tested administrative interface paths including:
                <ul>
                    <li>Application administration panels</li>
                    <li>Database management interfaces</li>
                    <li>Server infrastructure endpoints</li>
                    <li>Configuration and setup interfaces</li>
                    <li>Development and debugging interfaces</li>
                    <li>DVWA-specific vulnerability modules</li>
                </ul>
            </li>
            <li><strong>Special Testing:</strong> Specifically tested DVWA authentication bypass vulnerability with default credentials (gordonb:abc123)</li>
            <li><strong>Testing Locations:</strong> Checked interfaces relative to both:
                <ul>
                    <li>DVWA application root ({self.dvwa_url})</li>
                    <li>Server root ({self.base_url})</li>
                </ul>
            </li>
            <li><strong>Risk Assessment:</strong> Categorized findings by interface type and potential risk level</li>
        </ol>
    </div>"""

        if accessible_findings:
            html_content += """
    <div class="section">
        <h2>Findings Summary</h2>
        <table>
            <tr>
                <th>Interface Path</th>
                <th>Status Code</th>
                <th>Type</th>
                <th>Risk Level</th>
                <th>Tested At</th>
            </tr>"""
            
            # Sort findings: High risk first, then Medium, then Low
            sorted_findings = sorted(accessible_findings, key=lambda x: (
                0 if x.get('risk_level') == 'High' else
                1 if x.get('risk_level') == 'Medium' else
                2
            ))
            
            # Add findings to table
            for finding in sorted_findings:
                risk_class = finding.get('risk_level', 'Low').lower()
                interface_type = finding.get('interface_type', 'Unknown')
                
                html_content += f"""
            <tr>
                <td><a href="{finding['url']}" target="_blank">{finding['url'].replace(self.base_url, '').replace(self.dvwa_url, '')}</a></td>
                <td>{finding['status_code']}</td>
                <td>{interface_type}</td>
                <td><span class="risk-tag risk-{risk_class}-tag">{finding.get('risk_level', 'Low')}</span></td>
                <td>{finding.get('tested_at', 'Unknown')}</td>
            </tr>"""
            
            html_content += """
        </table>
    </div>"""

            # Add detailed findings only for High/Medium risk
            significant_findings = [f for f in accessible_findings if f.get('risk_level') in ['High', 'Medium']]
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
                    interface_type = finding.get('interface_type', 'Unknown')
                    
                    html_content += f"""
        <div class="finding risk-{risk_class}">
            <h3>{finding['url'].replace(self.base_url, '').replace(self.dvwa_url, '')}</h3>
            <p><strong>Risk Level:</strong> <span class="risk-tag risk-{risk_class}-tag">{finding.get('risk_level', 'Low')}</span> 
               <span class="interface-type-tag">{interface_type}</span></p>
            <p><strong>HTTP Status:</strong> {finding['status_code']}</p>
            <p><strong>Content Type:</strong> {finding['content_type']}</p>
            <p><strong>Content Length:</strong> {finding['content_length']} bytes</p>
            <p><strong>Tested At:</strong> {finding.get('tested_at', 'Unknown')}</p>"""
                    
                    if finding.get('description'):
                        html_content += f"""
            <p><strong>Description:</strong> {finding.get('description')}</p>"""
                    
                    if finding.get('redirect_url'):
                        html_content += f"""
            <p><strong>Redirects To:</strong> {finding['redirect_url']}</p>"""
                    
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
            <strong>Good News:</strong> No administrative interfaces were found accessible during this test.
        </div>
    </div>"""

        # Add interface type breakdown
        interface_categories = {}
        for finding in accessible_findings:
            interface_type = finding.get('interface_type', 'Unknown')
            if interface_type in interface_categories:
                interface_categories[interface_type] += 1
            else:
                interface_categories[interface_type] = 1
        
        html_content += """
    <div class="section">
        <h2>Interface Type Breakdown</h2>
        <table>
            <tr>
                <th>Interface Type</th>
                <th>Count</th>
            </tr>"""
        
        for interface_type, count in interface_categories.items():
            html_content += f"""
            <tr>
                <td>{interface_type}</td>
                <td>{count}</td>
            </tr>"""
        
        html_content += """
        </table>
    </div>"""

        html_content += """
    <div class="section">
        <h2>Remediation Recommendations</h2>
        <ol>
            <li><strong>Access Control:</strong> Implement proper authentication and authorization for all administrative interfaces</li>
            <li><strong>Interface Removal:</strong> Remove or disable unused administrative interfaces from production environments</li>
            <li><strong>Network Segmentation:</strong> Restrict access to administrative interfaces to trusted networks only</li>
            <li><strong>Web Server Configuration:</strong> Configure web server to deny access to common administrative paths</li>
            <li><strong>Regular Auditing:</strong> Implement automated scanning for exposed administrative interfaces</li>
            <li><strong>Strong Authentication:</strong> Use multi-factor authentication for high-risk administrative interfaces</li>
            <li><strong>DVWA Security:</strong> In production environments, ensure DVWA vulnerability modules are properly secured or removed</li>
        </ol>
        <h3>Apache Configuration Example:</h3>
        <div class="code-block">
# Deny access to common administrative paths<br>
<LocationMatch "(admin|administrator|phpmyadmin|server-status|phpinfo|vulnerabilities)"><br>
    Require ip 127.0.0.1<br>
    Require ip ::1<br>
</LocationMatch><br><br>
# Deny access to configuration files<br>
<FilesMatch "\\.(conf|config|ini|env)$"><br>
    Require all denied<br>
</FilesMatch>
        </div>
        <h3>Nginx Configuration Example:</h3>
        <div class="code-block">
# Deny access to common administrative paths<br>
location ~* (admin|administrator|phpmyadmin|server-status|phpinfo|vulnerabilities) {{<br>
    allow 127.0.0.1;<br>
    allow ::1;<br>
    deny all;<br>
}}<br><br>
# Deny access to configuration files<br>
location ~* \\.(conf|config|ini|env)$ {{<br>
    deny all;<br>
    return 404;<br>
}}
        </div>
    </div>

    <div class="section">
        <h2>Conclusion</h2>
        <p>The administrative interface enumeration assessment evaluated the web application and server infrastructure for exposed management endpoints that could provide unauthorized access or sensitive information. """
        
        if len(high_risk) > 0:
            html_content += f"""The assessment identified {len(high_risk)} high-risk administrative interfaces that require immediate attention to prevent potential unauthorized access to sensitive functionality."""
        elif len(medium_risk) > 0:
            html_content += f"""The assessment found {len(medium_risk)} medium-risk administrative interfaces that should be reviewed for proper access controls."""
        elif len(accessible_findings) > 0:
            html_content += f"""The assessment found {len(accessible_findings)} accessible interfaces, but none posed high security risks. This indicates reasonable access controls, though further hardening is recommended."""
        else:
            html_content += "The assessment found no accessible administrative interfaces, indicating good security practices for interface exposure."
        
        html_content += """</p>
        <p>This assessment demonstrates the importance of proper access controls and network segmentation for administrative interfaces. Organizations should regularly audit their environments for exposed management endpoints and ensure they are properly protected. Special attention should be paid to educational and testing applications like DVWA which contain intentional vulnerabilities.</p>
    </div>

    <div class="footer">
        <p>Generated by DVWA Admin Interfaces Test Script | OTG-CONFIG-005</p>
        <p>This is a security testing report for educational purposes</p>
    </div>
</body>
</html>"""
        
        # Save report
        os.makedirs('reports', exist_ok=True)
        report_path = 'reports/DVWA_Admin_Interfaces_Report.html'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Report generated: {report_path}")
        return report_path

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='DVWA Enumerate Admin Interfaces (OTG-CONFIG-005)')
    parser.add_argument('--url', default='http://localhost', help='Base URL of the web server (default: http://localhost)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    
    args = parser.parse_args()
    
    print("[+] DVWA Enumerate Infrastructure and Application Admin Interfaces (OTG-CONFIG-005)")
    print(f"[+] Target URL: {args.url}")
    print("[+] Starting security assessment...")
    
    # Initialize tester
    tester = DVWAAdminInterfaceTester(base_url=args.url)
    
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