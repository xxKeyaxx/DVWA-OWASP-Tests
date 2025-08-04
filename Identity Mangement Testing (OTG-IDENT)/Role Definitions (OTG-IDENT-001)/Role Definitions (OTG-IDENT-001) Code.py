import requests
from bs4 import BeautifulSoup
import os
from datetime import datetime

def get_csrf_token(session, url):
    """Extract CSRF token from DVWA pages"""
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        if token_input:
            return token_input['value']
        return None
    except Exception as e:
        print(f"Error getting CSRF token: {e}")
        return None

def login_dvwa(session, base_url, username, password):
    """Login to DVWA and return success status"""
    try:
        login_url = f"{base_url}/login.php"
        token = get_csrf_token(session, login_url)
        
        if not token:
            return False
            
        login_data = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': token
        }
        
        response = session.post(login_url, data=login_data, allow_redirects=False)
        return response.status_code in [302, 200] and ('index.php' in response.headers.get('Location', '') or 'Welcome' in response.text)
    except Exception as e:
        print(f"Login error: {e}")
        return False

def set_security_level(session, base_url, security_level):
    """Set DVWA security level"""
    try:
        security_url = f"{base_url}/security.php"
        token = get_csrf_token(session, security_url)
        
        if not token:
            return False
            
        security_data = {
            'security': security_level,
            'seclev_submit': 'Submit',
            'user_token': token
        }
        
        response = session.post(security_url, data=security_data)
        return response.status_code == 200
    except Exception as e:
        print(f"Error setting security level: {e}")
        return False

def test_auth_bypass(session, base_url):
    """Test authentication bypass vulnerabilities"""
    findings = []
    
    try:
        # Test access to auth bypass page
        auth_bypass_url = f"{base_url}/vulnerabilities/authbypass/"
        response = session.get(auth_bypass_url)
        
        if response.status_code == 200 and 'authentication bypass' in response.text.lower():
            findings.append({
                'vulnerability': 'Authentication Bypass Access',
                'endpoint': auth_bypass_url,
                'evidence': f"Status: {response.status_code}, Auth bypass functionality accessible",
                'severity': 'High'
            })
            
            # Try to access other users' data
            my_account_url = f"{auth_bypass_url}?id=1"
            response2 = session.get(my_account_url)
            
            if response2.status_code == 200 and ('admin' in response2.text.lower() or 'user information' in response2.text.lower()):
                findings.append({
                    'vulnerability': 'IDOR - Unauthorized User Data Access',
                    'endpoint': my_account_url,
                    'evidence': f"Status: {response2.status_code}, Accessed admin user data via ID parameter",
                    'severity': 'High'
                })
                
    except Exception as e:
        print(f"Error testing auth bypass: {e}")
    
    return findings

def test_csrf_vulnerabilities(session, base_url):
    """Test CSRF vulnerabilities that could allow privilege escalation"""
    findings = []
    
    try:
        # Test access to CSRF page
        csrf_url = f"{base_url}/vulnerabilities/csrf/"
        response = session.get(csrf_url)
        
        if response.status_code == 200 and 'csrf' in response.text.lower():
            findings.append({
                'vulnerability': 'CSRF Functionality Access',
                'endpoint': csrf_url,
                'evidence': f"Status: {response.status_code}, CSRF change password functionality accessible",
                'severity': 'Medium'
            })
            
            # Check if we can see/change admin password (this would be a serious issue)
            # Look for password change forms
            if 'password' in response.text.lower() and 'change' in response.text.lower():
                findings.append({
                    'vulnerability': 'Potential Admin Password Modification Access',
                    'endpoint': csrf_url,
                    'evidence': f"Status: {response.status_code}, Password change functionality accessible to regular user",
                    'severity': 'High'
                })
                
    except Exception as e:
        print(f"Error testing CSRF: {e}")
    
    return findings

def test_admin_functionality_access(session, base_url):
    """Test access to admin-only functionality as regular user"""
    findings = []
    
    # Key admin pages to test
    admin_pages = [
        'security.php',
        'users.php',
        'phpinfo.php'
    ]
    
    for page in admin_pages:
        try:
            url = f"{base_url}/{page}"
            response = session.get(url)
            
            if response.status_code == 200:
                if page == 'security.php' and 'dvwa security' in response.text.lower():
                    findings.append({
                        'vulnerability': 'Unauthorized Security Level Access',
                        'endpoint': url,
                        'evidence': f"Status: {response.status_code}, Can access security level controls as regular user",
                        'severity': 'High'
                    })
                elif page == 'users.php' and ('user management' in response.text.lower() or 'add new user' in response.text.lower()):
                    findings.append({
                        'vulnerability': 'Unauthorized User Management Access',
                        'endpoint': url,
                        'evidence': f"Status: {response.status_code}, Can manage users as regular user",
                        'severity': 'High'
                    })
                elif page == 'phpinfo.php' and 'php version' in response.text.lower():
                    findings.append({
                        'vulnerability': 'Unauthorized PHP Info Access',
                        'endpoint': url,
                        'evidence': f"Status: {response.status_code}, PHP configuration information disclosed",
                        'severity': 'Medium'
                    })
                    
        except Exception as e:
            print(f"Error testing {page}: {e}")
    
    return findings

def test_setup_and_config_access(session, base_url):
    """Test access to setup and configuration files"""
    findings = []
    
    sensitive_paths = [
        'setup.php',
        'config/config.inc.php',
        'config/',
        '.git/',
        'backup/',
        'install/'
    ]
    
    for path in sensitive_paths:
        try:
            url = f"{base_url}/{path}"
            response = session.get(url)
            
            if response.status_code == 200:
                if path == 'setup.php' and ('setup' in response.text.lower() or 'installation' in response.text.lower()):
                    findings.append({
                        'vulnerability': 'Unauthorized Setup Access',
                        'endpoint': url,
                        'evidence': f"Status: {response.status_code}, Setup/reinstall functionality accessible",
                        'severity': 'High'
                    })
                elif 'config' in path and ('db_' in response.text or 'database' in response.text):
                    findings.append({
                        'vulnerability': 'Configuration File Access',
                        'endpoint': url,
                        'evidence': f"Status: {response.status_code}, Configuration content accessible",
                        'severity': 'High'
                    })
                elif 'index of' in response.text.lower():
                    findings.append({
                        'vulnerability': 'Directory Listing Enabled',
                        'endpoint': url,
                        'evidence': f"Status: {response.status_code}, Directory listing found",
                        'severity': 'Medium'
                    })
                    
        except Exception as e:
            print(f"Error testing {path}: {e}")
    
    return findings

def test_privilege_escalation_opportunities(session, base_url):
    """Test specific privilege escalation opportunities"""
    findings = []
    
    # Test if regular user can access privileged vulnerability modules
    privileged_modules = [
        'vulnerabilities/upload/',
        'vulnerabilities/exec/',
        'vulnerabilities/fileincl/',
        'vulnerabilities/fi/.?page=include.php'
    ]
    
    for module in privileged_modules:
        try:
            url = f"{base_url}/{module}"
            response = session.get(url)
            
            if response.status_code == 200:
                # Check if we get access to privileged functionality
                privileged_indicators = [
                    'file upload',
                    'command execution',
                    'execute command',
                    'include file',
                    'upload file'
                ]
                
                for indicator in privileged_indicators:
                    if indicator in response.text.lower():
                        findings.append({
                            'vulnerability': 'Privileged Module Access',
                            'endpoint': url,
                            'evidence': f"Status: {response.status_code}, Accessed '{indicator}' functionality as regular user",
                            'severity': 'High'
                        })
                        break
                        
        except Exception as e:
            print(f"Error testing {module}: {e}")
    
    return findings

def generate_html_report(findings, base_url):
    """Generate OSCP-style HTML report"""
    
    # Count severity levels
    high_count = len([f for f in findings if f['severity'] == 'High'])
    medium_count = len([f for f in findings if f['severity'] == 'Medium'])
    low_count = len([f for f in findings if f['severity'] == 'Low'])
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - OTG-IDENT-001</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #1e1e1e;
            color: #d4d4d4;
            margin: 0;
            padding: 20px;
        }}
        .header {{
            background-color: #2d2d30;
            padding: 20px;
            border-left: 4px solid #4ec9b0;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #4ec9b0;
            margin: 0;
            font-size: 24px;
        }}
        .header p {{
            margin: 5px 0;
            color: #9cdcfe;
        }}
        .section {{
            background-color: #2d2d30;
            margin-bottom: 20px;
            padding: 20px;
            border-left: 3px solid #c586c0;
        }}
        .section-title {{
            color: #4ec9b0;
            font-size: 20px;
            margin-top: 0;
            margin-bottom: 15px;
        }}
        .finding-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        .finding-table th {{
            background-color: #3c3c3c;
            color: #4ec9b0;
            padding: 12px;
            text-align: left;
            border: 1px solid #555;
        }}
        .finding-table td {{
            padding: 10px;
            border: 1px solid #555;
            vertical-align: top;
        }}
        .high {{ color: #f48771; }}
        .medium {{ color: #e2c08d; }}
        .low {{ color: #75beff; }}
        .summary-box {{
            background-color: #3c3c3c;
            padding: 15px;
            margin: 15px 0;
            border-left: 3px solid #4ec9b0;
        }}
        pre {{
            background-color: #3c3c3c;
            padding: 15px;
            overflow-x: auto;
            border: 1px solid #555;
            color: #d4d4d4;
        }}
        .evidence {{
            font-size: 12px;
            white-space: pre-wrap;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Target:</strong> {base_url}</p>
        <p><strong>Test ID:</strong> OTG-IDENT-001 - Testing Role Definitions</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <p>This assessment evaluated the role-based access control implementation of the DVWA application 
        according to OWASP Testing Guide v4 - OTG-IDENT-001. Testing was performed using a regular user account 
        (gordonb/abc123) to identify improper role enforcement, privilege escalation opportunities, and unauthorized 
        access to administrative functionality.</p>
        
        <div class="summary-box">
            <p><strong>Findings Summary:</strong></p>
            <p><span class="high">High Severity:</span> {high_count} findings</p>
            <p><span class="medium">Medium Severity:</span> {medium_count} findings</p>
            <p><span class="low">Low Severity:</span> {low_count} findings</p>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Methodology</h2>
        <p>The testing methodology followed OWASP Testing Guide v4 guidelines for testing role definitions:</p>
        <ul>
            <li>Authenticated as regular user (gordonb/abc123) to test access control enforcement</li>
            <li>Attempted access to administrative functions and privileged operations</li>
            <li>Tested authentication bypass vulnerabilities (IDOR)</li>
            <li>Evaluated CSRF vulnerabilities that could allow privilege escalation</li>
            <li>Attempted direct access to restricted resources and configuration files</li>
            <li>Tested access to privileged vulnerability modules</li>
        </ul>
    </div>

    <div class="section">
        <h2 class="section-title">Test Results</h2>
        <table class="finding-table">
            <tr>
                <th>Vulnerability</th>
                <th>Endpoint</th>
                <th>Evidence</th>
                <th>Severity</th>
            </tr>"""
    
    if findings:
        for finding in findings:
            severity_class = finding['severity'].lower()
            html_content += f"""
            <tr>
                <td>{finding['vulnerability']}</td>
                <td>{finding['endpoint']}</td>
                <td class="evidence">{finding['evidence']}</td>
                <td class="{severity_class}">{finding['severity']}</td>
            </tr>"""
    else:
        html_content += """
            <tr>
                <td colspan="4" style="text-align: center;">No vulnerabilities found during testing</td>
            </tr>"""
    
    html_content += f"""
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Risk Assessment</h2>
        <p>Based on the findings, the application shows varying degrees of role definition enforcement issues. 
        High severity findings indicate potential for unauthorized administrative access and privilege escalation, 
        which could lead to complete system compromise.</p>
    </div>

    <div class="section">
        <h2 class="section-title">Recommendations</h2>
        <ol>
            <li>Implement strict server-side role validation for all administrative functions</li>
            <li>Enforce proper session management and role assignment mechanisms</li>
            <li>Disable directory listing and restrict access to sensitive paths</li>
            <li>Implement proper CSRF protection tokens for all state-changing operations</li>
            <li>Prevent IDOR vulnerabilities through proper user context validation</li>
            <li>Regularly audit role-based access controls and privilege assignments</li>
            <li>Ensure all privileged operations require proper authorization checks</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li>OWASP Testing Guide v4 - OTG-IDENT-001: Testing Role Definitions</li>
            <li>OWASP Top 10 - A01:2021-Broken Access Control</li>
            <li>OWASP Top 10 - A04:2021-Insecure Design</li>
            <li>CWE-284: Improper Access Control</li>
            <li>CWE-352: Cross-Site Request Forgery (CSRF)</li>
            <li>CWE-639: Authorization Bypass Through User-Controlled Key</li>
        </ul>
    </div>
</body>
</html>"""
    
    # Save the report
    with open("OTG-IDENT-001_Report.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print("HTML report generated: OTG-IDENT-001_Report.html")

def main():
    # Configuration
    base_url = "http://localhost/dvwa"
    regular_username = "gordonb"  # Regular user in DVWA
    regular_password = "abc123"
    
    # Create session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    print("[*] Starting OTG-IDENT-001 Role Definitions Test")
    print(f"[*] Target: {base_url}")
    print(f"[*] User: {regular_username}")
    
    # Check if DVWA is accessible
    try:
        response = session.get(base_url, timeout=10)
        if response.status_code != 200:
            print("[-] DVWA is not accessible. Please ensure XAMPP is running and DVWA is installed.")
            return
        print("[+] DVWA is accessible")
    except Exception as e:
        print(f"[-] Error connecting to DVWA: {e}")
        return
    
    # Login as regular user
    print("[*] Logging in as regular user...")
    if not login_dvwa(session, base_url, regular_username, regular_password):
        print("[-] Failed to login as regular user")
        return
    print("[+] Successfully logged in as regular user")
    
    # Set security level to low for comprehensive testing
    print("[*] Setting security level to low...")
    if set_security_level(session, base_url, 'low'):
        print("[+] Security level set to low")
    else:
        print("[-] Failed to set security level")
    
    # Collect findings
    findings = []
    
    print("[*] Testing authentication bypass vulnerabilities...")
    findings.extend(test_auth_bypass(session, base_url))
    
    print("[*] Testing CSRF vulnerabilities...")
    findings.extend(test_csrf_vulnerabilities(session, base_url))
    
    print("[*] Testing admin functionality access...")
    findings.extend(test_admin_functionality_access(session, base_url))
    
    print("[*] Testing setup and configuration access...")
    findings.extend(test_setup_and_config_access(session, base_url))
    
    print("[*] Testing privilege escalation opportunities...")
    findings.extend(test_privilege_escalation_opportunities(session, base_url))
    
    # Generate report
    print("[*] Generating HTML report...")
    generate_html_report(findings, base_url)
    
    # Summary
    high_count = len([f for f in findings if f['severity'] == 'High'])
    medium_count = len([f for f in findings if f['severity'] == 'Medium'])
    low_count = len([f for f in findings if f['severity'] == 'Low'])
    
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    print(f"High Severity Issues:   {high_count}")
    print(f"Medium Severity Issues: {medium_count}")
    print(f"Low Severity Issues:    {low_count}")
    print(f"Total Findings:         {len(findings)}")
    print("="*50)
    print("Report saved as: OTG-IDENT-001_Report.html")

if __name__ == "__main__":
    main()