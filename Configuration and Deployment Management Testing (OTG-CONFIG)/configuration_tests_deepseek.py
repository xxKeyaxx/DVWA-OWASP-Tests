import requests
from bs4 import BeautifulSoup
import re
import os
import socket
from datetime import datetime
from time import sleep
from urllib.parse import urljoin
import traceback

# Configuration
BASE_URL = "http://localhost/dvwa/"
LOGIN_URL = BASE_URL + "login.php"
SECURITY_URL = BASE_URL + "security.php"
REPORT_FILE = "configuration_test.html"

# Common payloads and patterns
COMMON_ADMIN_PATHS = [
    '/phpmyadmin/', '/admin/', '/dashboard/', 
    '/manager/', '/adminer.php', '/webadmin/'
]

BACKUP_PATTERNS = [
    '.bak', '.old', '.backup', '~',
    '_backup', '.zip', '.tar.gz'
]

SENSITIVE_EXTENSIONS = [
    '.inc', '.config', '.env', '.swp',
    '.tmp', '.log', '.sql', '.yml'
]

def init_session():
    """Authenticate to DVWA and set security level"""
    try:
        session = requests.Session()
        
        # Retrieve login token
        response = session.get(LOGIN_URL)
        soup = BeautifulSoup(response.text, 'html.parser')
        user_token = soup.find('input', {'name': 'user_token'}).get('value') if soup.find('input', {'name': 'user_token'}) else ''
        
        # Login
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        response = session.post(LOGIN_URL, data=login_data)
        
        # Verify login
        if 'Welcome' not in response.text:
            raise Exception("DVWA login failed: Incorrect credentials or server error")
        
        # Set security level
        session.get(SECURITY_URL, params={'security': 'low', 'security_token': user_token})
        
        return session
    except Exception as e:
        raise Exception(f"Session initialization failed: {str(e)}")

def test_platform_config(session, base_url):
    """OTG-CONFIG-002: Application Platform Configuration"""
    findings = []
    status = "Success"
    error_info = ""
    
    try:
        # Test 1: Trigger verbose errors
        test_urls = [
            (base_url + "invalid-page", "Nonexistent page"),
            (base_url + "vulnerabilities/exec/&invalid-param", "Malformed input"),
            (base_url + "vulnerabilities/sqli/?id='", "SQL error trigger")
        ]
        
        for url, test_name in test_urls:
            response = session.get(url)
            if response.status_code == 200 and any(keyword in response.text for keyword in ["error", "warning", "stack trace", "on line"]):
                findings.append({
                    'title': 'Verbose Error Messages',
                    'description': f'Exposed error details at: {test_name}',
                    'url': url,
                    'risk': 'Medium',
                    'evidence': response.text[:1000] + "..." if len(response.text) > 1000 else response.text
                })
            sleep(0.5)  # Rate limiting
        
        # Test 2: Debug mode detection
        response = session.get(base_url)
        if "debug=true" in response.text.lower() or "debug_mode=on" in response.text.lower():
            findings.append({
                'title': 'Debug Mode Active',
                'description': 'Application appears to be in debug mode',
                'url': base_url,
                'risk': 'High',
                'evidence': "Debug indicators found in page source"
            })
        
        if not findings:
            findings.append({
                'title': 'No Verbose Errors Found',
                'description': 'No debug information or verbose errors were detected',
                'url': base_url,
                'risk': 'Info',
                'evidence': 'Test completed without findings'
            })
            
    except Exception as e:
        status = "Failed"
        error_info = f"Error: {str(e)}\n{traceback.format_exc()}"
        findings.append({
            'title': 'Test Execution Failed',
            'description': f'Could not complete platform configuration tests',
            'url': base_url,
            'risk': 'High',
            'evidence': f"Error details: {str(e)}"
        })
    
    return {
        'test_id': 'OTG-CONFIG-002',
        'name': 'Application Platform Configuration',
        'status': status,
        'error_info': error_info,
        'findings': findings
    }

def test_file_extensions(session, base_url):
    """OTG-CONFIG-003: File Extensions Handling"""
    findings = []
    status = "Success"
    error_info = ""
    
    try:
        test_files = [
            "index.php", "login.php", "setup.php", 
            ".htaccess", "config.inc.php"
        ]
        
        for file in test_files:
            for ext in SENSITIVE_EXTENSIONS:
                test_url = urljoin(base_url, file + ext)
                try:
                    response = session.head(test_url, timeout=3)
                    
                    if response.status_code == 200:
                        # Verify we're getting source code
                        content_response = session.get(test_url)
                        if "<?php" in content_response.text or "Configuration" in content_response.text:
                            findings.append({
                                'title': f'Sensitive Extension Accessible: {ext}',
                                'description': f'Source code exposure via {file}{ext}',
                                'url': test_url,
                                'risk': 'Medium',
                                'evidence': content_response.text[:500] + "..." if len(content_response.text) > 500 else content_response.text
                            })
                        sleep(0.5)
                except:
                    continue
        
        if not findings:
            findings.append({
                'title': 'No Sensitive Files Found',
                'description': 'No exposed files with sensitive extensions detected',
                'url': base_url,
                'risk': 'Info',
                'evidence': 'Test completed without findings'
            })
            
    except Exception as e:
        status = "Failed"
        error_info = f"Error: {str(e)}\n{traceback.format_exc()}"
        findings.append({
            'title': 'Test Execution Failed',
            'description': f'Could not complete file extension tests',
            'url': base_url,
            'risk': 'High',
            'evidence': f"Error details: {str(e)}"
        })
    
    return {
        'test_id': 'OTG-CONFIG-003',
        'name': 'File Extensions Handling',
        'status': status,
        'error_info': error_info,
        'findings': findings
    }

def find_backup_files(session, base_url):
    """OTG-CONFIG-004: Old/Backup Files"""
    findings = []
    status = "Success"
    error_info = ""
    
    try:
        core_files = ["index.php", "login.php", "setup.php", "config.inc.php"]
        found_files = False
        
        for file in core_files:
            for pattern in BACKUP_PATTERNS:
                test_url = urljoin(base_url, file + pattern)
                try:
                    response = session.head(test_url, timeout=3)
                    
                    if response.status_code == 200:
                        found_files = True
                        content_response = session.get(test_url)
                        evidence = content_response.text[:1000] + "..." if len(content_response.text) > 1000 else content_response.text
                        
                        # Check for sensitive content
                        sensitive_keywords = ["password", "database", "user", "secret", "key"]
                        sensitive_found = any(keyword in content_response.text.lower() for keyword in sensitive_keywords)
                        
                        findings.append({
                            'title': f'Backup File Found: {file}{pattern}',
                            'description': f'Potential sensitive backup file accessible',
                            'url': test_url,
                            'risk': 'High' if sensitive_found else 'Medium',
                            'evidence': evidence
                        })
                        sleep(0.5)
                except:
                    continue
        
        if not found_files:
            findings.append({
                'title': 'No Backup Files Found',
                'description': 'No common backup files were detected',
                'url': base_url,
                'risk': 'Info',
                'evidence': 'Test completed without findings'
            })
            
    except Exception as e:
        status = "Failed"
        error_info = f"Error: {str(e)}\n{traceback.format_exc()}"
        findings.append({
            'title': 'Test Execution Failed',
            'description': f'Could not complete backup file search',
            'url': base_url,
            'risk': 'High',
            'evidence': f"Error details: {str(e)}"
        })
    
    return {
        'test_id': 'OTG-CONFIG-004',
        'name': 'Old/Backup Files',
        'status': status,
        'error_info': error_info,
        'findings': findings
    }

def test_admin_interfaces(session, base_url):
    """OTG-CONFIG-005: Admin Interfaces"""
    findings = []
    status = "Success"
    error_info = ""
    
    try:
        found_interfaces = False
        
        for path in COMMON_ADMIN_PATHS:
            test_url = "http://localhost" + path
            try:
                response = session.get(test_url, timeout=3)
                
                if response.status_code == 200:
                    found_interfaces = True
                    # Check if authentication is required
                    requires_auth = any(keyword in response.text.lower() 
                                        for keyword in ["login", "username", "password"])
                    
                    findings.append({
                        'title': f'Admin Interface Accessible: {path}',
                        'description': f'{"Protected" if requires_auth else "Unprotected"} admin interface found',
                        'url': test_url,
                        'risk': 'Medium' if requires_auth else 'High',
                        'evidence': f"Status: {response.status_code}, Title: {BeautifulSoup(response.text, 'html.parser').title.string if BeautifulSoup(response.text, 'html.parser').title else 'None'}"
                    })
                sleep(0.5)
            except:
                continue
        
        if not found_interfaces:
            findings.append({
                'title': 'No Admin Interfaces Found',
                'description': 'No common admin interfaces were detected',
                'url': base_url,
                'risk': 'Info',
                'evidence': 'Test completed without findings'
            })
            
    except Exception as e:
        status = "Failed"
        error_info = f"Error: {str(e)}\n{traceback.format_exc()}"
        findings.append({
            'title': 'Test Execution Failed',
            'description': f'Could not complete admin interface tests',
            'url': base_url,
            'risk': 'High',
            'evidence': f"Error details: {str(e)}"
        })
    
    return {
        'test_id': 'OTG-CONFIG-005',
        'name': 'Admin Interfaces',
        'status': status,
        'error_info': error_info,
        'findings': findings
    }

def test_http_methods(session, base_url):
    """OTG-CONFIG-006: HTTP Methods"""
    findings = []
    status = "Success"
    error_info = ""
    
    try:
        test_url = urljoin(base_url, "vulnerabilities/upload/")
        dangerous_methods = ['PUT', 'DELETE', 'TRACE']
        dangerous_found = False
        
        try:
            # First check OPTIONS to see allowed methods
            response = session.request('OPTIONS', test_url, timeout=3)
            allowed_methods = response.headers.get('Allow', '').split(',')
            allowed_methods = [m.strip().upper() for m in allowed_methods]
            
            for method in dangerous_methods:
                if method in allowed_methods:
                    dangerous_found = True
                    # Test actual method execution
                    test_response = session.request(method, test_url)
                    
                    findings.append({
                        'title': f'Dangerous Method Allowed: {method}',
                        'description': f'Potential modification vulnerability via {method}',
                        'url': test_url,
                        'risk': 'High',
                        'evidence': f"Status: {test_response.status_code}, Allowed Methods: {', '.join(allowed_methods)}"
                    })
                    sleep(0.5)
        except requests.exceptions.RequestException as e:
            findings.append({
                'title': 'HTTP Methods Test Failed',
                'description': str(e),
                'url': test_url,
                'risk': 'Info',
                'evidence': ''
            })
        
        if not dangerous_found and not findings:
            findings.append({
                'title': 'No Dangerous Methods Allowed',
                'description': 'No dangerous HTTP methods (PUT/DELETE/TRACE) were allowed',
                'url': test_url,
                'risk': 'Info',
                'evidence': f"Allowed methods: {', '.join(allowed_methods) if 'allowed_methods' in locals() else 'Not detected'}"
            })
            
    except Exception as e:
        status = "Failed"
        error_info = f"Error: {str(e)}\n{traceback.format_exc()}"
        findings.append({
            'title': 'Test Execution Failed',
            'description': f'Could not complete HTTP methods tests',
            'url': base_url,
            'risk': 'High',
            'evidence': f"Error details: {str(e)}"
        })
    
    return {
        'test_id': 'OTG-CONFIG-006',
        'name': 'HTTP Methods',
        'status': status,
        'error_info': error_info,
        'findings': findings
    }

def test_hsts(session, base_url):
    """OTG-CONFIG-007: HSTS Testing"""
    findings = []
    status = "Success"
    error_info = ""
    
    try:
        try:
            # Try HTTPS even though DVWA is typically HTTP
            https_url = base_url.replace("http://", "https://")
            response = session.get(https_url, verify=False, timeout=3)
            
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            if hsts_header:
                findings.append({
                    'title': 'HSTS Implemented',
                    'description': f'HSTS header found: {hsts_header}',
                    'url': https_url,
                    'risk': 'Low',
                    'evidence': f"HSTS Policy: {hsts_header}"
                })
            else:
                findings.append({
                    'title': 'HSTS Not Implemented',
                    'description': 'Missing Strict-Transport-Security header',
                    'url': https_url,
                    'risk': 'Low',
                    'evidence': 'No HSTS header detected'
                })
        except requests.exceptions.SSLError:
            findings.append({
                'title': 'HTTPS Not Available',
                'description': 'Could not establish HTTPS connection',
                'url': base_url,
                'risk': 'Info',
                'evidence': 'DVWA running on HTTP only'
            })
        except requests.exceptions.RequestException as e:
            findings.append({
                'title': 'HSTS Test Failed',
                'description': str(e),
                'url': base_url,
                'risk': 'Info',
                'evidence': ''
            })
            
    except Exception as e:
        status = "Failed"
        error_info = f"Error: {str(e)}\n{traceback.format_exc()}"
        findings.append({
            'title': 'Test Execution Failed',
            'description': f'Could not complete HSTS tests',
            'url': base_url,
            'risk': 'High',
            'evidence': f"Error details: {str(e)}"
        })
    
    return {
        'test_id': 'OTG-CONFIG-007',
        'name': 'HSTS Testing',
        'status': status,
        'error_info': error_info,
        'findings': findings
    }

def test_crossdomain_policy(session, base_url):
    """OTG-CONFIG-008: RIA Cross Domain Policy"""
    findings = []
    status = "Success"
    error_info = ""
    
    try:
        policy_files = ['/crossdomain.xml', '/clientaccesspolicy.xml']
        found_policies = False
        
        for policy_file in policy_files:
            test_url = urljoin(base_url, policy_file)
            try:
                response = session.get(test_url, timeout=3)
                
                if response.status_code == 200:
                    found_policies = True
                    # Analyze policy content
                    policy_content = response.text
                    is_permissive = any(tag in policy_content 
                                        for tag in ['allow-access-from domain="*"', 
                                                    '<allow-http-request-headers-from domain="*"'])
                    
                    findings.append({
                        'title': f'Cross-Domain Policy Found: {policy_file}',
                        'description': f'{"Permissive" if is_permissive else "Restricted"} cross-domain policy',
                        'url': test_url,
                        'risk': 'Medium' if is_permissive else 'Low',
                        'evidence': policy_content[:500] + "..." if len(policy_content) > 500 else policy_content
                    })
                sleep(0.5)
            except:
                continue
        
        if not found_policies:
            findings.append({
                'title': 'No Cross-Domain Policies Found',
                'description': 'No crossdomain.xml or clientaccesspolicy.xml files detected',
                'url': base_url,
                'risk': 'Info',
                'evidence': 'Test completed without findings'
            })
            
    except Exception as e:
        status = "Failed"
        error_info = f"Error: {str(e)}\n{traceback.format_exc()}"
        findings.append({
            'title': 'Test Execution Failed',
            'description': f'Could not complete cross-domain policy tests',
            'url': base_url,
            'risk': 'High',
            'evidence': f"Error details: {str(e)}"
        })
    
    return {
        'test_id': 'OTG-CONFIG-008',
        'name': 'RIA Cross Domain Policy',
        'status': status,
        'error_info': error_info,
        'findings': findings
    }

def generate_html_report(test_results):
    """Generate OWASP-style HTML report with detailed test status"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate test cards
    test_cards_html = ""
    for test in test_results:
        status_class = "success" if test['status'] == "Success" else "failed"
        test_cards_html += f"""
        <div class="test-card {status_class}">
            <h3>{test['test_id']}: {test['name']}</h3>
            <div class="test-status">Status: {test['status']}</div>
            <div class="findings-count">Findings: {len(test['findings'])}</div>
        </div>
        """
    
    # Generate findings sections
    findings_html = ""
    for test in test_results:
        status_class = test['status'].lower()
        findings_html += f"""
        <section class="test-section">
            <div class="section-header">
                <h2>
                    {test['test_id']}: {test['name']}
                    <span class="test-status-badge {status_class}">{test['status']}</span>
                </h2>
            </div>
            <div class="section-content">
        """
        
        if test['error_info']:
            findings_html += f"""
            <div class="error-info">
                <h3>Test Execution Error</h3>
                <pre>{test['error_info']}</pre>
            </div>
            """
        
        for finding in test['findings']:
            risk_class = f"risk-{finding['risk'].lower()}" if finding['risk'] != 'Info' else 'risk-info'
            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <h3>{finding['title']}</h3>
                    <div class="risk-label {risk_class}">{finding['risk']} Risk</div>
                </div>
                <p><strong>Description:</strong> {finding['description']}</p>
                <p><strong>URL:</strong> <span class="url">{finding['url']}</span></p>
                <div class="evidence-container">
                    <h4>Evidence:</h4>
                    <pre>{finding['evidence']}</pre>
                </div>
            </div>
            """
        
        findings_html += "</div></section>"
    
    # Full HTML template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP Configuration Test Report</title>
    <style>
        /* Base styles */
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background-color: #222;
            color: white;
            padding: 2rem;
            text-align: center;
            margin-bottom: 2rem;
            border-bottom: 5px solid #c00;
            border-radius: 5px;
        }}
        
        h1, h2, h3 {{
            color: #222;
        }}
        
        .report-meta {{
            background-color: #e9ecef;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .report-meta div {{
            background-color: white;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }}
        
        /* Test summary cards */
        .test-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .test-card {{
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 1.5rem;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        
        .test-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .test-card.success {{
            border-top: 4px solid #28a745;
        }}
        
        .test-card.failed {{
            border-top: 4px solid #dc3545;
        }}
        
        .test-status {{
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .test-card.success .test-status {{
            color: #28a745;
        }}
        
        .test-card.failed .test-status {{
            color: #dc3545;
        }}
        
        /* Test sections */
        .test-section {{
            margin-bottom: 2.5rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
            background-color: white;
        }}
        
        .section-header {{
            background-color: #343a40;
            color: white;
            padding: 1.2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .test-status-badge {{
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: bold;
        }}
        
        .test-status-badge.success {{
            background-color: #28a745;
        }}
        
        .test-status-badge.failed {{
            background-color: #dc3545;
        }}
        
        .section-content {{
            padding: 1.8rem;
        }}
        
        /* Findings styles */
        .finding {{
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.8rem;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .risk-label {{
            padding: 0.3rem 0.8rem;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85rem;
        }}
        
        .risk-high {{
            background-color: #ffcccc;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }}
        
        .risk-medium {{
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeeba;
        }}
        
        .risk-low {{
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }}
        
        .risk-info {{
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }}
        
        .url {{
            font-family: monospace;
            background-color: #e9ecef;
            padding: 0.3rem 0.5rem;
            border-radius: 3px;
            word-break: break-all;
            display: inline-block;
            margin: 0.3rem 0;
        }}
        
        pre {{
            background-color: #2d2d2d;
            color: #f8f8f2;
            padding: 1.2rem;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Consolas', monospace;
            margin-top: 0.8rem;
            max-height: 300px;
            overflow-y: auto;
            line-height: 1.4;
        }}
        
        .error-info {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 5px;
            padding: 1.2rem;
            margin-bottom: 1.5rem;
        }}
        
        footer {{
            text-align: center;
            margin-top: 3rem;
            padding: 1.5rem;
            color: #6c757d;
            font-size: 0.9rem;
            border-top: 1px solid #dee2e6;
        }}
        
        /* Responsive design */
        @media (max-width: 768px) {{
            .test-summary {{
                grid-template-columns: 1fr;
            }}
            
            .section-header {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .test-status-badge {{
                margin-top: 0.5rem;
            }}
            
            .finding-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }}
            
            .risk-label {{
                align-self: flex-start;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <h1>OWASP Configuration & Deployment Test Report</h1>
        <p>Comprehensive security assessment of application configuration</p>
    </header>
    
    <div class="report-meta">
        <div><strong>Generated:</strong> {timestamp}</div>
        <div><strong>Target:</strong> {BASE_URL}</div>
        <div><strong>Tests:</strong> OTG-CONFIG-002 to OTG-CONFIG-008</div>
    </div>
    
    <section class="executive-summary">
        <h2>Executive Summary</h2>
        <div class="test-summary">
            {test_cards_html}
        </div>
    </section>
    
    <section class="detailed-findings">
        <h2>Detailed Test Results</h2>
        {findings_html}
    </section>
    
    <footer>
        <p>Generated by OWASP Security Testing Toolkit | {timestamp}</p>
        <p>Report includes findings from all completed tests with error details for failed tests</p>
    </footer>
</body>
</html>
    """
    
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return REPORT_FILE

if __name__ == "__main__":
    print("[*] Starting Configuration & Deployment Testing")
    print(f"[*] Target: {BASE_URL}")
    
    test_results = []
    
    try:
        # Initialize session
        print("[*] Authenticating to DVWA...")
        session = init_session()
        print("[+] Authentication successful")
        
        # Define tests
        tests = [
            ("OTG-CONFIG-002", "Application Platform Configuration", test_platform_config),
            ("OTG-CONFIG-003", "File Extensions Handling", test_file_extensions),
            ("OTG-CONFIG-004", "Old/Backup Files", find_backup_files),
            ("OTG-CONFIG-005", "Admin Interfaces", test_admin_interfaces),
            ("OTG-CONFIG-006", "HTTP Methods", test_http_methods),
            ("OTG-CONFIG-007", "HSTS Testing", test_hsts),
            ("OTG-CONFIG-008", "RIA Cross Domain Policy", test_crossdomain_policy)
        ]
        
        # Execute tests
        for test_id, test_name, test_func in tests:
            print(f"\n[+] Running {test_id}: {test_name}")
            try:
                result = test_func(session, BASE_URL)
                test_results.append(result)
                status_msg = "SUCCESS" if result['status'] == "Success" else "FAILED"
                print(f"[{status_msg}] {test_id} completed with {len(result['findings'])} findings")
                if result['error_info']:
                    print(f"    Error details: {result['error_info'].splitlines()[0]}")
            except Exception as e:
                print(f"[-] Critical error executing {test_id}: {str(e)}")
                test_results.append({
                    'test_id': test_id,
                    'name': test_name,
                    'status': "Failed",
                    'error_info': f"Unhandled exception: {str(e)}\n{traceback.format_exc()}",
                    'findings': [{
                        'title': 'Test Execution Failed',
                        'description': 'Critical error prevented test execution',
                        'url': BASE_URL,
                        'risk': 'High',
                        'evidence': f"Error: {str(e)}"
                    }]
                })
        
        # Generate report
        print("\n[+] Generating comprehensive test report...")
        report_path = generate_html_report(test_results)
        print(f"[+] Report generated: {report_path}")
        
        # Final statistics
        success_count = sum(1 for t in test_results if t['status'] == "Success")
        failed_count = len(test_results) - success_count
        total_findings = sum(len(t['findings']) for t in test_results)
        
        print("\n[+] Testing completed")
        print(f"    Tests executed: {len(test_results)}")
        print(f"    Tests successful: {success_count}")
        print(f"    Tests failed: {failed_count}")
        print(f"    Total findings: {total_findings}")
        
    except Exception as e:
        print(f"[-] Critical testing failure: {str(e)}")
        traceback.print_exc()
        # Generate emergency report if possible
        if test_results:
            try:
                generate_html_report(test_results)
                print(f"[!] Partial report generated with available results")
            except:
                print(f"[-] Failed to generate even partial report")