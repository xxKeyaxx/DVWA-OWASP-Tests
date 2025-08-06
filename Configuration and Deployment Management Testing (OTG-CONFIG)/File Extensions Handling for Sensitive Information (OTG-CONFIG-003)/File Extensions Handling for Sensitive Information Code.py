#!/usr/bin/env python3
"""
DVWA File Extension Handling Test (OTG-CONFIG-003)
Automated testing script for identifying insecure file extension handling
"""

import requests
import os
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
from datetime import datetime
import argparse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWATester:
    def __init__(self, base_url="http://localhost"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'DVWA-Tester/1.0'})
        self.findings = []
        self.test_files = [
            # PHP information files (High Risk)
            'phpinfo.php', 'info.php', 'php_info.php', 'phpinfo.php.bak', 'info.php.bak',
            'test.php', 'debug.php', 'dev.php',
            
            # PHP files
            'config.php', 'config.php.bak', 'config.php~', 'config.php.save', 'config.php.old',
            'database.php', 'database.php.bak', 'settings.php', 'settings.php.bak',
            'login.php.bak', 'index.php.bak',
            
            # Configuration files
            '.env', '.env.local', '.env.production', '.env.dev',
            'wp-config.php', 'wp-config.php.bak',
            '.htaccess', '.htpasswd',
            
            # Backup files
            'backup.sql', 'database.sql', 'data.sql', 'db.sql',
            'backup.zip', 'backup.tar.gz', 'site_backup.zip',
            'config.bak', 'configuration.bak', 'settings.bak',
            
            # Log files
            'access.log', 'error.log', 'debug.log', 'app.log',
            
            # Other sensitive files
            '.git/config', '.git/HEAD', '.svn/entries',
            'composer.json', 'package.json', 'package-lock.json',
            'web.config', 'web.config.bak'
        ]
        
        # Common directories to test (including root with empty string)
        self.test_directories = [
            'dvwa',  # Root directory (this should test http://localhost/dvwa/phpinfo.php)
            'config/', 'includes/', 'inc/', 'lib/', 'libs/', 'src/',
            'backup/', 'backups/', 'tmp/', 'temp/', 'uploads/', 'files/',
            'admin/', 'logs/', 'log/', 'data/', '.git/', '.svn/'
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
            
            # Get login page to extract CSRF token - FIXED URL CONSTRUCTION
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

    def is_content_interesting(self, content, url):
        """Determine if the content is potentially sensitive"""
        content_lower = content.lower()
        
        # Skip common non-sensitive pages
        if any(skip_phrase in content_lower for skip_phrase in [
            'welcome to nginx',
            'it works!',
            'apache http server',
            'index of /',
            'directory listing for',
            'default web page',
            '<title>index of',
            '404 not found',
            '403 forbidden',
            'forbidden'
        ]):
            return False, 'Low'
        
        # Check for phpinfo pages (High Risk)
        if 'phpinfo()' in content or 'PHP Version' in content or '<h1 class="p">PHP Version' in content:
            return True, 'High'
        
        # Check for sensitive content
        sensitive_indicators = [
            # Configuration/credentials
            ('password', 'High'),
            ('passwd', 'High'),
            ('secret', 'High'),
            ('api_key', 'High'),
            ('token', 'Medium'),
            ('database', 'Medium'),
            ('mysql', 'Medium'),
            ('postgresql', 'Medium'),
            ('mongodb', 'Medium'),
            ('connection', 'Medium'),
            # Source code indicators
            ('<?php', 'High'),
            ('mysql_connect', 'High'),
            ('mysqli_connect', 'High'),
            ('pdo(', 'Medium'),
            ('new mysqli', 'Medium'),
            # File content indicators
            ('create table', 'Medium'),  # SQL
            ('insert into', 'Medium'),   # SQL
            ('select *', 'Low'),         # Generic SQL
        ]
        
        # Check for high-value file types that are always interesting when accessible
        always_interesting_extensions = [
            '.env', '.sql', '.log', '.bak', '.backup', '.config', '.key'
        ]
        
        # If it's an always-interesting file type, flag it regardless of content
        for ext in always_interesting_extensions:
            if ext in url.lower():
                return True, 'High'
        
        # Check for sensitive indicators in content
        highest_risk = 'Low'
        found_sensitive = False
        
        for indicator, risk_level in sensitive_indicators:
            if indicator in content_lower:
                found_sensitive = True
                if risk_level == 'High':
                    return True, 'High'
                elif risk_level == 'Medium' and highest_risk == 'Low':
                    highest_risk = 'Medium'
        
        return found_sensitive, highest_risk

    def test_file_access(self, file_path):
        """Test access to a specific file"""
        try:
            full_url = urljoin(self.dvwa_url, file_path)
            logger.info(f"Testing: {full_url}")
            
            # Send GET request
            response = self.session.get(full_url, timeout=10)
            
            # Analyze response
            result = {
                'url': full_url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', 'unknown'),
                'accessible': response.status_code == 200,
                'sensitive_content': False,
                'risk_level': 'Low'
            }
            
            # Check for sensitive content only if file is accessible
            if response.status_code == 200 and len(response.content) > 0:
                # Skip if it's just a redirect or very small generic content
                if len(response.content) < 50 and ('<html>' not in response.text.lower()):
                    result['risk_level'] = 'Low'
                    return result
                
                # Check if content is interesting
                is_interesting, risk_level = self.is_content_interesting(response.text, full_url)
                result['sensitive_content'] = is_interesting
                result['risk_level'] = risk_level
                
                if is_interesting:
                    logger.info(f"Found potentially sensitive file: {file_path} (Risk: {risk_level})")
            
            return result
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for {file_path}: {str(e)}")
            return {
                'url': urljoin(self.dvwa_url, file_path),
                'status_code': 0,
                'content_length': 0,
                'content_type': 'error',
                'accessible': False,
                'sensitive_content': False,
                'risk_level': 'Low',
                'error': str(e)
            }

    def run_tests(self):
        """Run all file extension tests"""
        logger.info("Starting file extension handling tests...")
        logger.info(f"Testing root directory and {len(self.test_directories)-1} subdirectories")
        logger.info(f"DVWA URL: {self.dvwa_url}")
        
        tested_urls = set()
        accessible_files = 0
        sensitive_files = 0
        
        # Explicitly test some key files in root first
        root_test_files = ['phpinfo.php', 'info.php', 'test.php']
        logger.info("Testing key files in root directory first...")
        for filename in root_test_files:
            file_path = filename  # This will test at root
            if file_path not in tested_urls:
                tested_urls.add(file_path)
                result = self.test_file_access(file_path)
                if result['accessible']:
                    self.findings.append(result)
                    accessible_files += 1
                    if result['sensitive_content'] or result['risk_level'] in ['High', 'Medium']:
                        sensitive_files += 1
                        logger.info(f"Found sensitive file: {file_path} (Risk: {result['risk_level']})")
                time.sleep(0.05)
        
        # Now test all directories and files
        for directory in self.test_directories:
            for filename in self.test_files:
                file_path = os.path.join(directory, filename).replace('\\', '/')
                
                # Avoid duplicate tests
                if file_path in tested_urls:
                    continue
                    
                tested_urls.add(file_path)
                
                result = self.test_file_access(file_path)
                
                # Store findings
                if result['accessible']:
                    self.findings.append(result)
                    accessible_files += 1
                    if result['sensitive_content'] or result['risk_level'] in ['High', 'Medium']:
                        sensitive_files += 1
                        logger.info(f"Found sensitive file: {file_path} (Risk: {result['risk_level']})")
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.05)
        
        logger.info(f"Completed testing. Found {accessible_files} accessible files ({sensitive_files} potentially sensitive) out of {len(tested_urls)} tested.")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Sort findings by risk level
        high_risk = [f for f in self.findings if f.get('risk_level') == 'High']
        medium_risk = [f for f in self.findings if f.get('risk_level') == 'Medium']
        low_risk = [f for f in self.findings if f.get('risk_level') == 'Low']
        
        # Count accessible files
        accessible_count = len(self.findings)
        
        # Generate HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DVWA File Extension Handling Test Report</title>
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
        <p>File Extension Handling Assessment (OTG-CONFIG-003)</p>
        <p>Generated on: {timestamp}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report presents the findings of a security assessment focused on testing file extension handling for sensitive information disclosure in the Damn Vulnerable Web Application (DVWA). The test was conducted according to OWASP Testing Guide v4 methodology OTG-CONFIG-003.</p>
        
        <div class="summary-stats">
            <div class="stat-box total-stat">
                <div class="stat-number">{accessible_count}</div>
                <div>Total Accessible Files</div>
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
        
        if len(high_risk) > 0 or len(medium_risk) > 0:
            html_content += """
        <div class="warning">
            <strong>Security Alert:</strong> Potentially sensitive files were found accessible. These should be reviewed and secured immediately.
        </div>"""
        else:
            html_content += """
        <div class="success">
            <strong>Good Security Posture:</strong> No high or medium risk sensitive files were found during this test.
        </div>"""
        
        html_content += f"""
    </div>

    <div class="section">
        <h2>Test Overview</h2>
        <h3>OWASP Testing Guide - OTG-CONFIG-003</h3>
        <p><strong>Objective:</strong> Test File Extensions Handling for Sensitive Information</p>
        <p><strong>Description:</strong> Verify that the web server does not serve sensitive files with backup, temporary, or development extensions that could expose configuration details, source code, or credentials.</p>
        <p><strong>Target:</strong> {self.dvwa_url}</p>
        <p><strong>Test Files Checked:</strong> {len(self.test_files)} common sensitive file patterns</p>
        <p><strong>Directories Scanned:</strong> Root directory plus {len(self.test_directories)-1} common web application subdirectories</p>
        <p><strong>Key Test Files Include:</strong> phpinfo.php, config files, backup files, log files, .env files</p>
    </div>

    <div class="section">
        <h2>Methodology</h2>
        <p>The testing methodology included the following steps:</p>
        <ol>
            <li><strong>Authentication:</strong> Logged into DVWA with default credentials</li>
            <li><strong>Reconnaissance:</strong> Identified common directories for sensitive files including root directory</li>
            <li><strong>Enumeration:</strong> Tested access to files with sensitive extensions including:
                <ul>
                    <li>PHP information files (phpinfo.php, info.php) - tested in root and subdirectories</li>
                    <li>Configuration files (.php, .env, .config, .ini)</li>
                    <li>Backup files (.bak, .backup, .old, ~)</li>
                    <li>Database dumps (.sql)</li>
                    <li>Log files (.log)</li>
                    <li>Version control files (.git, .svn)</li>
                </ul>
            </li>
            <li><strong>Content Analysis:</strong> Evaluated HTTP responses for sensitive content disclosure using intelligent pattern matching</li>
        </ol>
    </div>"""

        if self.findings:
            html_content += """
    <div class="section">
        <h2>Findings Summary</h2>
        <table>
            <tr>
                <th>File Path</th>
                <th>Status Code</th>
                <th>Content Type</th>
                <th>Content Length</th>
                <th>Risk Level</th>
            </tr>"""
            
            # Sort findings: High risk first, then Medium, then Low
            sorted_findings = sorted(self.findings, key=lambda x: (
                0 if x.get('risk_level') == 'High' else
                1 if x.get('risk_level') == 'Medium' else
                2
            ))
            
            # Add findings to table
            for finding in sorted_findings:
                risk_class = finding.get('risk_level', 'Low').lower()
                html_content += f"""
            <tr>
                <td><a href="{finding['url']}" target="_blank">{finding['url'].replace(self.dvwa_url, '')}</a></td>
                <td>{finding['status_code']}</td>
                <td>{finding['content_type']}</td>
                <td>{finding['content_length']}</td>
                <td><span class="risk-tag risk-{risk_class}-tag">{finding.get('risk_level', 'Low')}</span></td>
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
                    html_content += f"""
        <div class="finding risk-{risk_class}">
            <h3>{finding['url'].replace(self.dvwa_url, '')}</h3>
            <p><strong>Risk Level:</strong> <span class="risk-tag risk-{risk_class}-tag">{finding.get('risk_level', 'Low')}</span></p>
            <p><strong>HTTP Status:</strong> {finding['status_code']}</p>
            <p><strong>Content Type:</strong> {finding['content_type']}</p>
            <p><strong>Content Length:</strong> {finding['content_length']} bytes</p>"""
                    
                    if finding.get('sensitive_content'):
                        html_content += """
            <p><strong>⚠️ SENSITIVE CONTENT DETECTED</strong></p>"""
                    
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
            <strong>Good News:</strong> No files were found accessible during this test. This suggests that the application has proper file access controls in place.
        </div>
    </div>"""

        html_content += """
    <div class="section">
        <h2>Remediation Recommendations</h2>
        <ol>
            <li><strong>File Access Control:</strong> Implement proper file access controls to prevent serving of sensitive files in all directories including root</li>
            <li><strong>Web Server Configuration:</strong> Configure web server to deny access to common backup and temporary file extensions</li>
            <li><strong>Remove Sensitive Files:</strong> Delete or secure development files like phpinfo.php, test.php from production (especially in root directory)</li>
            <li><strong>File Permissions:</strong> Set appropriate file permissions to restrict access to sensitive files</li>
            <li><strong>Deployment Process:</strong> Ensure development and backup files are not deployed to production</li>
            <li><strong>Regular Auditing:</strong> Implement regular scanning for sensitive file exposure in all directories</li>
        </ol>
        <h3>Apache Configuration Example:</h3>
        <div class="code-block">
# Deny access to sensitive file extensions<br>
<FilesMatch "\\.(bak|backup|old|orig|save|swp|tmp|log|sql|config|env|key|info)$"><br>
    Require all denied<br>
</FilesMatch><br><br>
# Deny access to sensitive file names<br>
<FilesMatch "(phpinfo|info|test|debug)\\.php$"><br>
    Require all denied<br>
</FilesMatch><br><br>
# Deny access to hidden files<br>
<FilesMatch "^\\."gt;<br>
    Require all denied<br>
</FilesMatch>
        </div>
        <h3>Nginx Configuration Example:</h3>
        <div class="code-block">
# Deny access to sensitive file extensions<br>
location ~* \\.(bak|backup|old|orig|save|swp|tmp|log|sql|config|env|key|info)$ {{<br>
    deny all;<br>
    return 404;<br>
}}<br><br>
# Deny access to sensitive file names<br>
location ~* (phpinfo|info|test|debug)\\.php$ {{<br>
    deny all;<br>
    return 404;<br>
}}<br><br>
# Deny access to hidden files<br>
location ~* /\\..* {{<br>
    deny all;<br>
    return 404;<br>
}}
        </div>
    </div>

    <div class="section">
        <h2>Conclusion</h2>
        <p>The file extension handling test evaluated the web application's exposure of sensitive files through improper file access controls. """
        
        if len(high_risk) > 0 or len(medium_risk) > 0:
            html_content += f"""The assessment identified {len(high_risk)} high-risk and {len(medium_risk)} medium-risk issues that require immediate attention to prevent unauthorized access to configuration files, backup data, and other sensitive resources."""
        elif accessible_count > 0:
            html_content += f"""The assessment found {accessible_count} accessible files, but none contained sensitive information. This indicates reasonable file access controls, though further hardening is recommended."""
        else:
            html_content += "The assessment found no accessible sensitive files, indicating good file access control practices."
        
        html_content += """</p>
        <p>This assessment demonstrates the importance of proper file management and access controls in web applications to prevent information disclosure vulnerabilities. Files like phpinfo.php can expose critical system information and should never be accessible in production environments, especially in the root directory.</p>
    </div>

    <div class="footer">
        <p>Generated by DVWA File Extension Handling Test Script | OTG-CONFIG-003</p>
        <p>This is a security testing report for educational purposes</p>
    </div>
</body>
</html>"""
        
        # Save report
        os.makedirs('reports', exist_ok=True)
        report_path = 'reports/DVWA_File_Extension_Test_Report.html'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Report generated: {report_path}")
        return report_path

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='DVWA File Extension Handling Test (OTG-CONFIG-003)')
    parser.add_argument('--url', default='http://localhost', help='Base URL of the web server (default: http://localhost)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    
    args = parser.parse_args()
    
    print("[+] DVWA File Extension Handling Test (OTG-CONFIG-003)")
    print(f"[+] Target URL: {args.url}")
    print("[+] Starting security assessment...")
    
    # Initialize tester
    tester = DVWATester(base_url=args.url)
    
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