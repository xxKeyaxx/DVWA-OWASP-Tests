#!/usr/bin/env python3
"""
DVWA Review Old, Backup and Unreferenced Files (OTG-CONFIG-004)
Automated testing script for identifying backup and unreferenced files
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
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWABackupTester:
    def __init__(self, base_url="http://localhost"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'DVWA-Backup-Tester/1.0'})
        self.findings = []
        self.referenced_files = set()
        self.crawled_urls = set()
        
        # Common backup file extensions and patterns
        self.backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.tmp', '.temp', '.save', 
            '.swp', '~', '.copy', '.bak.sql', '.sql.bak', '.sql.old',
            '.tar', '.tar.gz', '.zip', '.rar', '.7z', '.gz'
        ]
        
        # Common backup filenames
        self.backup_filenames = [
            'config', 'configuration', 'settings', 'database', 'db', 'backup',
            'install', 'readme', 'changelog', 'license', 'composer', 'package',
            'wp-config', 'web.config', '.env', '.htaccess', 'robots'
        ]
        
        # Common directories to test
        self.test_directories = [
            '', 'config/', 'includes/', 'inc/', 'lib/', 'libs/', 'src/',
            'backup/', 'backups/', 'tmp/', 'temp/', 'uploads/', 'files/',
            'admin/', 'logs/', 'log/', 'data/', 'sql/', 'db/', 'database/'
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

    def crawl_site(self, max_depth=2):
        """Crawl DVWA to find referenced files"""
        logger.info("Starting site crawl to identify referenced files...")
        
        # Start with main pages
        start_urls = [
            urljoin(self.dvwa_url, ''),
            urljoin(self.dvwa_url, 'index.php'),
            urljoin(self.dvwa_url, 'instructions.php'),
            urljoin(self.dvwa_url, 'setup.php')
        ]
        
        # Add vulnerability modules
        vuln_modules = [
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
        
        for module in vuln_modules:
            start_urls.append(urljoin(self.dvwa_url, module))
        
        to_crawl = [(url, 0) for url in start_urls]
        
        while to_crawl:
            current_url, depth = to_crawl.pop(0)
            
            if current_url in self.crawled_urls or depth > max_depth:
                continue
                
            self.crawled_urls.add(current_url)
            logger.debug(f"Crawling: {current_url}")
            
            try:
                response = self.session.get(current_url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links, scripts, images, stylesheets
                    for tag in soup.find_all(['a', 'link', 'script', 'img']):
                        href = tag.get('href') or tag.get('src')
                        if href:
                            # Resolve relative URLs
                            full_url = urljoin(current_url, href)
                            # Only consider local files
                            if urlparse(full_url).netloc == urlparse(self.dvwa_url).netloc:
                                self.referenced_files.add(full_url)
                                # Add to crawl queue if it's an HTML page
                                if depth < max_depth and ('.php' in full_url or full_url.endswith('/')):
                                    to_crawl.append((full_url, depth + 1))
                                    
            except Exception as e:
                logger.warning(f"Error crawling {current_url}: {str(e)}")
                continue
            
            time.sleep(0.1)  # Be nice to the server
        
        logger.info(f"Finished crawling. Found {len(self.referenced_files)} referenced files.")

    def is_backup_file(self, filename):
        """Check if a filename indicates a backup file"""
        filename_lower = filename.lower()
        
        # Check for backup extensions
        for ext in self.backup_extensions:
            if filename_lower.endswith(ext):
                return True
        
        # Check for backup patterns in filename
        for pattern in ['backup', 'bak', 'old', 'copy']:
            if pattern in filename_lower and not filename_lower.startswith(pattern):
                return True
                
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
                'risk_level': 'Low',
                'is_backup': self.is_backup_file(os.path.basename(file_path)),
                'is_referenced': full_url in self.referenced_files
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
                
                # Increase risk for backup files with sensitive content
                if result['is_backup'] and is_interesting:
                    result['risk_level'] = 'High'
                elif result['is_backup']:
                    result['risk_level'] = 'Medium'
                
                if is_interesting or result['is_backup']:
                    logger.info(f"Found suspicious file: {file_path} (Risk: {result['risk_level']})")
            
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
                'is_backup': self.is_backup_file(os.path.basename(file_path)),
                'is_referenced': False,
                'error': str(e)
            }

    def generate_backup_filename_variations(self):
        """Generate common backup filename variations"""
        variations = []
        
        for filename in self.backup_filenames:
            # Add common backup extensions
            for ext in self.backup_extensions:
                variations.append(f"{filename}{ext}")
                variations.append(f"{filename}.php{ext}")
                variations.append(f"{filename}.inc{ext}")
                variations.append(f"{filename}.conf{ext}")
            
            # Add common backup suffixes
            suffixes = ['.bak', '.backup', '.old', '.orig', '.copy', '~']
            for suffix in suffixes:
                variations.append(f"{filename}{suffix}")
                variations.append(f"{filename}.php{suffix}")
                variations.append(f"{filename}.inc{suffix}")
        
        return variations

    def run_tests(self):
        """Run all backup file tests"""
        logger.info("Starting backup and unreferenced file tests...")
        logger.info(f"DVWA URL: {self.dvwa_url}")
        
        # First crawl the site to identify referenced files
        self.crawl_site()
        
        # Generate backup filename variations
        backup_variations = self.generate_backup_filename_variations()
        logger.info(f"Generated {len(backup_variations)} backup filename variations")
        
        tested_urls = set()
        accessible_files = 0
        suspicious_files = 0
        
        # Test generated backup filenames
        logger.info("Testing generated backup filename variations...")
        for directory in self.test_directories:
            for filename in backup_variations:
                file_path = os.path.join(directory, filename).replace('\\', '/')
                
                # Avoid duplicate tests
                if file_path in tested_urls:
                    continue
                    
                tested_urls.add(file_path)
                
                result = self.test_file_access(file_path)
                
                # Store findings for suspicious files
                if result['accessible'] and (result['is_backup'] or result['sensitive_content'] or not result['is_referenced']):
                    self.findings.append(result)
                    accessible_files += 1
                    if result['risk_level'] in ['High', 'Medium']:
                        suspicious_files += 1
                        logger.info(f"Found suspicious file: {file_path} (Risk: {result['risk_level']})")
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.05)
        
        # Test common backup files that might not be in our generated list
        common_backup_files = [
            'config.php.bak', 'config.php~', 'config.php.save',
            'database.sql', 'backup.sql', 'data.sql',
            'wp-config.php.bak', 'settings.php.bak',
            '.env.bak', '.env.backup',
            'web.config.bak', '.htaccess.bak',
            'composer.json.bak', 'package.json.bak',
            'readme.txt.bak', 'install.txt.bak'
        ]
        
        logger.info("Testing common backup files...")
        for directory in self.test_directories:
            for filename in common_backup_files:
                file_path = os.path.join(directory, filename).replace('\\', '/')
                
                # Avoid duplicate tests
                if file_path in tested_urls:
                    continue
                    
                tested_urls.add(file_path)
                
                result = self.test_file_access(file_path)
                
                # Store findings for suspicious files
                if result['accessible'] and (result['is_backup'] or result['sensitive_content'] or not result['is_referenced']):
                    self.findings.append(result)
                    accessible_files += 1
                    if result['risk_level'] in ['High', 'Medium']:
                        suspicious_files += 1
                        logger.info(f"Found suspicious file: {file_path} (Risk: {result['risk_level']})")
                
                # Small delay to avoid overwhelming the server
                time.sleep(0.05)
        
        logger.info(f"Completed testing. Found {accessible_files} accessible files ({suspicious_files} suspicious) out of {len(tested_urls)} tested.")

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
    <title>DVWA Backup Files Test Report</title>
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
        .backup-tag {{
            background-color: #9b59b6;
            color: white;
            margin-left: 10px;
        }}
        .unreferenced-tag {{
            background-color: #3498db;
            color: white;
            margin-left: 10px;
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
        <p>Review Old, Backup and Unreferenced Files (OTG-CONFIG-004)</p>
        <p>Generated on: {timestamp}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report presents the findings of a security assessment focused on identifying old, backup, and unreferenced files that could expose sensitive information in the Damn Vulnerable Web Application (DVWA). The test was conducted according to OWASP Testing Guide v4 methodology OTG-CONFIG-004.</p>
        
        <div class="summary-stats">
            <div class="stat-box total-stat">
                <div class="stat-number">{accessible_count}</div>
                <div>Total Suspicious Files</div>
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
            <strong>Security Alert:</strong> Potentially sensitive backup or unreferenced files were found accessible. These should be reviewed and secured immediately.
        </div>"""
        else:
            html_content += """
        <div class="success">
            <strong>Good Security Posture:</strong> No high or medium risk backup files were found during this test.
        </div>"""
        
        html_content += f"""
    </div>

    <div class="section">
        <h2>Test Overview</h2>
        <h3>OWASP Testing Guide - OTG-CONFIG-004</h3>
        <p><strong>Objective:</strong> Review Old, Backup and Unreferenced Files for Sensitive Information</p>
        <p><strong>Description:</strong> Identify backup copies of web files, temporary files, and unreferenced files that may contain sensitive information and are not intended to be served by the web server.</p>
        <p><strong>Target:</strong> {self.dvwa_url}</p>
        <p><strong>Files Tested:</strong> {len(self.findings)} potentially suspicious files</p>
        <p><strong>Directories Scanned:</strong> {len(self.test_directories)} common web application directories</p>
        <p><strong>Referenced Files Found:</strong> {len(self.referenced_files)} files identified during site crawl</p>
    </div>

    <div class="section">
        <h2>Methodology</h2>
        <p>The testing methodology included the following steps:</p>
        <ol>
            <li><strong>Authentication:</strong> Logged into DVWA with default credentials</li>
            <li><strong>Site Crawling:</strong> Enumerated referenced files through automated crawling</li>
            <li><strong>Backup File Generation:</strong> Created comprehensive list of backup filename variations including:
                <ul>
                    <li>Common backup extensions (.bak, .backup, .old, .orig, ~, etc.)</li>
                    <li>Temporary file patterns (.tmp, .temp, .save)</li>
                    <li>Editor backup files (.swp, ~)</li>
                    <li>Archive files (.zip, .tar.gz, .rar)</li>
                </ul>
            </li>
            <li><strong>File Enumeration:</strong> Tested for accessible backup and unreferenced files in:
                <ul>
                    <li>Root directory</li>
                    <li>Configuration directories (config/, includes/)</li>
                    <li>Backup directories (backup/, backups/)</li>
                    <li>Temporary directories (tmp/, temp/)</li>
                    <li>Database directories (sql/, db/)</li>
                </ul>
            </li>
            <li><strong>Content Analysis:</strong> Evaluated HTTP responses for sensitive content disclosure</li>
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
                <th>Tags</th>
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
                tags = []
                if finding.get('is_backup'):
                    tags.append('<span class="risk-tag backup-tag">BACKUP</span>')
                if not finding.get('is_referenced'):
                    tags.append('<span class="risk-tag unreferenced-tag">UNREFERENCED</span>')
                tags_html = ' '.join(tags) if tags else '<span class="risk-tag risk-low-tag">SUSPICIOUS</span>'
                
                html_content += f"""
            <tr>
                <td><a href="{finding['url']}" target="_blank">{finding['url'].replace(self.dvwa_url, '')}</a></td>
                <td>{finding['status_code']}</td>
                <td>{finding['content_type']}</td>
                <td>{finding['content_length']}</td>
                <td>{tags_html}</td>
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
                    tags = []
                    if finding.get('is_backup'):
                        tags.append('<span class="risk-tag backup-tag">BACKUP</span>')
                    if not finding.get('is_referenced'):
                        tags.append('<span class="risk-tag unreferenced-tag">UNREFERENCED</span>')
                    tags_html = ' '.join(tags) if tags else ''
                    
                    html_content += f"""
        <div class="finding risk-{risk_class}">
            <h3>{finding['url'].replace(self.dvwa_url, '')}</h3>
            <p><strong>Risk Level:</strong> <span class="risk-tag risk-{risk_class}-tag">{finding.get('risk_level', 'Low')}</span> {tags_html}</p>
            <p><strong>HTTP Status:</strong> {finding['status_code']}</p>
            <p><strong>Content Type:</strong> {finding['content_type']}</p>
            <p><strong>Content Length:</strong> {finding['content_length']} bytes</p>
            <p><strong>Referenced in Site:</strong> {'Yes' if finding.get('is_referenced') else 'No'}</p>"""
                    
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
            <strong>Good News:</strong> No suspicious backup or unreferenced files were found accessible during this test.
        </div>
    </div>"""

        html_content += """
    <div class="section">
        <h2>Remediation Recommendations</h2>
        <ol>
            <li><strong>Remove Backup Files:</strong> Delete all backup, temporary, and unreferenced files from production servers</li>
            <li><strong>Web Server Configuration:</strong> Configure web server to deny access to common backup file extensions</li>
            <li><strong>Development Process:</strong> Implement strict policies to prevent backup files from being deployed</li>
            <li><strong>File Permissions:</strong> Set appropriate file permissions to restrict access to sensitive files</li>
            <li><strong>Regular Auditing:</strong> Implement automated scanning for backup and temporary files</li>
            <li><strong>Editor Configuration:</strong> Configure editors to store backup files outside the web root</li>
        </ol>
        <h3>Apache Configuration Example:</h3>
        <div class="code-block">
# Deny access to backup and temporary files<br>
<FilesMatch "\\.(bak|backup|old|orig|tmp|temp|save|swp|copy|~)$"><br>
    Require all denied<br>
</FilesMatch><br><br>
# Deny access to archive files<br>
<FilesMatch "\\.(zip|tar|tar\\.gz|rar|7z)$"><br>
    Require all denied<br>
</FilesMatch><br><br>
# Deny access to hidden files<br>
<FilesMatch "^\\."gt;<br>
    Require all denied<br>
</FilesMatch>
        </div>
        <h3>Nginx Configuration Example:</h3>
        <div class="code-block">
# Deny access to backup and temporary files<br>
location ~* \\.(bak|backup|old|orig|tmp|temp|save|swp|copy|~)$ {{<br>
    deny all;<br>
    return 404;<br>
}}<br><br>
# Deny access to archive files<br>
location ~* \\.(zip|tar|tar\\.gz|rar|7z)$ {{<br>
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
        <p>The backup file assessment evaluated the web application's exposure of old, backup, and unreferenced files that could contain sensitive information. """
        
        if len(high_risk) > 0 or len(medium_risk) > 0:
            html_content += f"""The assessment identified {len(high_risk)} high-risk and {len(medium_risk)} medium-risk issues that require immediate attention to prevent unauthorized access to sensitive backup files and unreferenced resources."""
        elif accessible_count > 0:
            html_content += f"""The assessment found {accessible_count} suspicious files, but none contained highly sensitive information. This indicates reasonable file management practices, though further hardening is recommended."""
        else:
            html_content += "The assessment found no accessible backup or unreferenced files, indicating good file management practices."
        
        html_content += """</p>
        <p>This assessment demonstrates the importance of proper file management and access controls in web applications to prevent information disclosure through forgotten backup files. Organizations should implement strict policies to prevent backup files from being deployed to production environments.</p>
    </div>

    <div class="footer">
        <p>Generated by DVWA Backup Files Test Script | OTG-CONFIG-004</p>
        <p>This is a security testing report for educational purposes</p>
    </div>
</body>
</html>"""
        
        # Save report
        os.makedirs('reports', exist_ok=True)
        report_path = 'reports/DVWA_Backup_Files_Report.html'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Report generated: {report_path}")
        return report_path

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='DVWA Review Old, Backup and Unreferenced Files (OTG-CONFIG-004)')
    parser.add_argument('--url', default='http://localhost', help='Base URL of the web server (default: http://localhost)')
    parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
    parser.add_argument('--password', default='password', help='DVWA password (default: password)')
    
    args = parser.parse_args()
    
    print("[+] DVWA Review Old, Backup and Unreferenced Files (OTG-CONFIG-004)")
    print(f"[+] Target URL: {args.url}")
    print("[+] Starting security assessment...")
    
    # Initialize tester
    tester = DVWABackupTester(base_url=args.url)
    
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