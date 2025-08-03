import requests
from bs4 import BeautifulSoup
import datetime
import html

class DVWAPrivilegeEscalationTester:
    def __init__(self, base_url="http://localhost/dvwa"):
        self.base_url = base_url
        self.session = requests.Session()
        self.security_level = "low"
        self.test_results = []
        self.vulnerable_attempts = []

    def login_as_regular_user(self):
        """Login to DVWA as regular user (gordonb/abc123)"""
        try:
            # Get login page to extract CSRF token
            login_url = f"{self.base_url}/login.php"
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract CSRF token
            user_token = soup.find('input', {'name': 'user_token'})['value']
            
            # Perform login as regular user
            login_data = {
                'username': 'gordonb',
                'password': 'abc123',
                'Login': 'Login',
                'user_token': user_token
            }
            
            response = self.session.post(login_url, data=login_data)
            
            if "Login failed" in response.text:
                print("[-] Login failed for regular user")
                return False
            
            print("[+] Successfully logged in as regular user (gordonb)")
            return True
            
        except Exception as e:
            print(f"[-] Login error: {str(e)}")
            return False

    def set_security_level(self):
        """Set DVWA security level to low"""
        try:
            # Get security page to extract CSRF token
            security_url = f"{self.base_url}/security.php"
            response = self.session.get(security_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract CSRF token
            user_token = soup.find('input', {'name': 'user_token'})['value']
            
            # Set security to low
            security_data = {
                'security': self.security_level,
                'seclev_submit': 'Submit',
                'user_token': user_token
            }
            
            response = self.session.post(security_url, data=security_data)
            
            if self.security_level in response.text:
                print(f"[+] Security level set to {self.security_level}")
                return True
            
            print("[-] Failed to set security level")
            return False
            
        except Exception as e:
            print(f"[-] Security level error: {str(e)}")
            return False

    def test_database_reset_access(self):
        """Test access to database reset functionality (setup.php)"""
        print("[*] Testing access to database reset functionality...")
        
        try:
            setup_url = f"{self.base_url}/setup.php"
            response = self.session.get(setup_url)
            
            # Check if we can access the setup page
            can_access_setup = (
                response.status_code == 200 and
                "setup" in response.text.lower()
            )
            
            # Look for dangerous functionality
            has_reset_function = (
                "reset" in response.text.lower() or
                "create" in response.text.lower() or
                "database" in response.text.lower() or
                "table" in response.text.lower()
            )
            
            # Check if we're blocked
            is_blocked = (
                response.status_code in [403, 401, 302, 301] or
                "access denied" in response.text.lower() or
                "login" in response.text.lower() or
                "forbidden" in response.text.lower()
            )
            
            result = {
                'test_type': 'Database Reset Access',
                'url': '/setup.php',
                'description': 'Access to database initialization and reset functionality',
                'status_code': response.status_code,
                'response_length': len(response.text),
                'can_access_setup': can_access_setup,
                'has_reset_function': has_reset_function,
                'is_blocked': is_blocked,
                'vulnerable': can_access_setup and has_reset_function and not is_blocked
            }
            
            self.test_results.append(result)
            
            if result['vulnerable']:
                self.vulnerable_attempts.append(result)
                print("[!] VULNERABLE: Regular user can access database reset functionality!")
            elif is_blocked:
                print("[-] Database reset functionality properly restricted")
            else:
                print("[?] Ambiguous access to setup page")
                
        except Exception as e:
            print(f"[-] Error testing database reset access: {str(e)}")
            self.test_results.append({
                'test_type': 'Database Reset Access',
                'error': str(e),
                'vulnerable': False
            })

    def test_user_impersonation(self):
        """Test if we can impersonate other users"""
        print("[*] Testing user impersonation...")
        
        # Test accessing authbypass with different user IDs
        auth_bypass_url = f"{self.base_url}/vulnerabilities/authbypass/"
        
        try:
            # Test accessing admin user data (userid=1)
            response = self.session.get(auth_bypass_url, params={"userid": "1"})
            
            # Check if we can see admin data
            can_see_admin_data = (
                response.status_code == 200 and
                "admin" in response.text.lower() and
                ("yes" in response.text.lower() or "admin" in response.text.lower())
            )
            
            result = {
                'test_type': 'User Impersonation',
                'url': '/vulnerabilities/authbypass/?userid=1',
                'description': 'Attempting to access admin user data',
                'status_code': response.status_code,
                'response_length': len(response.text),
                'can_see_admin_data': can_see_admin_data,
                'vulnerable': can_see_admin_data
            }
            
            self.test_results.append(result)
            
            if can_see_admin_data:
                self.vulnerable_attempts.append(result)
                print("[!] VULNERABLE: Can access admin user data through impersonation!")
            else:
                print("[-] User impersonation properly restricted")
                
        except Exception as e:
            print(f"[-] Error testing user impersonation: {str(e)}")
            self.test_results.append({
                'test_type': 'User Impersonation',
                'error': str(e),
                'vulnerable': False
            })

    def test_configuration_file_access(self):
        """Test access to sensitive configuration files"""
        print("[*] Testing access to sensitive configuration...")
        
        sensitive_files = [
            {"url": "/config/config.inc.php", "name": "Config File"},
            {"url": "/phpinfo.php", "name": "PHP Info"}
        ]
        
        for file_info in sensitive_files:
            try:
                full_url = f"{self.base_url}{file_info['url']}"
                print(f"[*] Testing access to: {file_info['name']}")
                
                response = self.session.get(full_url)
                
                # Check if we can access sensitive information
                is_sensitive = (
                    response.status_code == 200 and
                    ("password" in response.text.lower() or
                     "config" in response.text.lower() or
                     "phpinfo" in response.text.lower() or
                     "database" in response.text.lower())
                )
                
                # Check if we're blocked
                is_blocked = (
                    response.status_code in [403, 401, 404, 302, 301] or
                    "access denied" in response.text.lower() or
                    "forbidden" in response.text.lower()
                )
                
                result = {
                    'test_type': 'Sensitive File Access',
                    'file_name': file_info['name'],
                    'url': file_info['url'],
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'is_sensitive': is_sensitive,
                    'is_blocked': is_blocked,
                    'vulnerable': is_sensitive and not is_blocked
                }
                
                self.test_results.append(result)
                
                if result['vulnerable']:
                    self.vulnerable_attempts.append(result)
                    print(f"[!] VULNERABLE: Can access {file_info['name']}!")
                elif is_blocked:
                    print(f"[-] {file_info['name']} properly restricted")
                else:
                    print(f"[?] Ambiguous access to {file_info['name']}")
                    
            except Exception as e:
                print(f"[-] Error testing {file_info['name']}: {str(e)}")
                self.test_results.append({
                    'test_type': 'Sensitive File Access',
                    'file_name': file_info['name'],
                    'error': str(e),
                    'vulnerable': False
                })

    def test_form_privilege_escalation(self):
        """Test if forms can be manipulated for privilege escalation"""
        print("[*] Testing form-based privilege escalation...")
        
        # Test various pages for hidden admin parameters
        test_pages = [
            "/index.php",
            "/security.php",
            "/vulnerabilities/sqli/"
        ]
        
        for page in test_pages:
            try:
                full_url = f"{self.base_url}{page}"
                print(f"[*] Testing forms on: {page}")
                
                response = self.session.get(full_url)
                
                # Look for hidden form fields that might indicate privilege controls
                hidden_fields = response.text.count('<input type="hidden"')
                admin_indicators = (
                    "admin" in response.text.lower() or
                    "role" in response.text.lower() or
                    "privilege" in response.text.lower()
                )
                
                result = {
                    'test_type': 'Form Analysis',
                    'page': page,
                    'hidden_fields_count': hidden_fields,
                    'admin_indicators': admin_indicators,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'vulnerable': False  # This is reconnaissance
                }
                
                self.test_results.append(result)
                print(f"[*] Found {hidden_fields} hidden fields, admin indicators: {admin_indicators}")
                
            except Exception as e:
                print(f"[-] Error analyzing forms on {page}: {str(e)}")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_filename = f"OSCP_Report_DVWA_PrivilegeEscalation_Localhost_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Determine if vulnerable
        vulnerable_count = len([r for r in self.test_results if r.get('vulnerable', False)])
        is_vulnerable = vulnerable_count > 0
            
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - DVWA Privilege Escalation</title>
    <style>
        body {{
            font-family: 'Courier New', Courier, monospace;
            background-color: #ffffff;
            color: #000000;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{
            color: #000080;
            border-bottom: 2px solid #000080;
            padding-bottom: 5px;
        }}
        h1 {{
            text-align: center;
            font-size: 2.5em;
        }}
        .header {{
            background-color: #f0f0f0;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #ccc;
        }}
        .section {{
            background-color: #f9f9f9;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            border: 1px solid #ddd;
        }}
        .code-block {{
            background-color: #f0f0f0;
            border: 1px solid #ccc;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
            margin: 10px 0;
            font-size: 0.9em;
        }}
        .vulnerable {{
            color: #cc0000;
            font-weight: bold;
        }}
        .safe {{
            color: #006600;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background-color: #e0e0e0;
            color: #000080;
        }}
        tr:nth-child(even) {{
            background-color: #f0f0f0;
        }}
        .payload {{
            color: #800080;
        }}
        .highlight {{
            background-color: #ffffcc;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        .risk-high {{
            background-color: #ffe6e6;
            border-left: 4px solid #cc0000;
            padding: 10px;
            margin: 10px 0;
        }}
        .risk-medium {{
            background-color: #fff2e6;
            border-left: 4px solid #ff9900;
            padding: 10px;
            margin: 10px 0;
        }}
        .risk-low {{
            background-color: #e6f2ff;
            border-left: 4px solid #0066cc;
            padding: 10px;
            margin: 10px 0;
        }}
        .disclaimer {{
            background-color: #fff8dc;
            border: 1px solid #ffd700;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Penetration Test Report</h1>
            <p><strong>Target:</strong> {self.base_url}</p>
            <p><strong>Date:</strong> {timestamp}</p>
            <p><strong>Author:</strong> Automated Security Agent</p>
            <p><strong>Classification:</strong> UNCLASSIFIED</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>This penetration test assessed meaningful access control vulnerabilities in the Damn Vulnerable Web Application (DVWA). Testing was performed by logging in as a regular user (gordonb/abc123) and attempting to access functionality or information that should be restricted from normal users.</p>
            
            <div class="disclaimer">
                <strong>Important Disclaimer:</strong> DVWA's design does not implement traditional user roles. All authenticated users have the same effective privileges in DVWA's architecture. The vulnerability modules are intentionally accessible by all authenticated users as part of DVWA's educational design.
            </div>
            """
        
        if is_vulnerable:
            html_content += """
            <div class="risk-high">
                <strong>Risk Level:</strong> HIGH
            </div>
            <p>Meaningful access control vulnerabilities were identified that allow regular users to access sensitive functionality or information that should be restricted.</p>
            """
        else:
            html_content += """
            <p><strong class="safe">No meaningful access control vulnerabilities detected.</strong> The application properly restricts access to sensitive functionality and information.</p>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Vulnerability Details</h2>
            <table>
                <tr><th>Category</th><th>Details</th></tr>
                <tr><td><strong>Name</strong></td><td>Meaningful Access Control Issues</td></tr>
                <tr><td><strong>OWASP ID</strong></td><td>OTG-AUTHZ-003</td></tr>
                """
        
        if is_vulnerable:
            html_content += """
                <tr><td><strong>Risk Level</strong></td><td><span class="vulnerable">HIGH</span></td></tr>
                """
        else:
            html_content += """
                <tr><td><strong>Risk Level</strong></td><td><span class="safe">LOW</span></td></tr>
                """
        
        html_content += f"""
                <tr><td><strong>Target</strong></td><td>{self.base_url}</td></tr>
                <tr><td><strong>Description</strong></td><td>The testing focused on identifying meaningful access control issues where regular users can access sensitive functionality or information that should be restricted. Note: DVWA does not implement traditional user roles - all authenticated users have the same privileges by design.</td></tr>
                <tr><td><strong>Impact</strong></td><td>Unauthorized access to sensitive data, potential system configuration changes, and violation of security policies.</td></tr>
                <tr><td><strong>Remediation</strong></td><td>Implement proper access controls for sensitive functionality and conduct regular security assessments.</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Technical Analysis</h2>
            <h3>Testing Methodology</h3>
            <p>The testing focused on meaningful access control issues:</p>
            <ol>
                <li><strong>Database Reset Access:</strong> Testing access to database initialization functionality</li>
                <li><strong>User Impersonation:</strong> Attempting to access other user's data</li>
                <li><strong>Configuration Access:</strong> Testing access to sensitive configuration files</li>
                <li><strong>Form Analysis:</strong> Examining forms for access control opportunities</li>
            </ol>

            <div class="disclaimer">
                <strong>Important Note:</strong> In DVWA's design:
                <ul>
                    <li>All logged-in users have the same effective privileges</li>
                    <li>The vulnerability modules are meant to be accessible by all authenticated users</li>
                    <li>There is no traditional admin/regular user distinction beyond authentication</li>
                    <li>This testing focuses on access to truly sensitive functionality, not general application features</li>
                </ul>
            </div>

            <h3>Test Results Summary</h3>
            <table>
                <tr>
                    <th>Test Type</th>
                    <th>Target</th>
                    <th>Status Code</th>
                    <th>Vulnerable</th>
                    <th>Description</th>
                </tr>"""
        
        # Add test results to report
        for result in self.test_results:
            vulnerable_class = "vulnerable" if result.get('vulnerable', False) else "safe"
            vulnerable_text = "YES" if result.get('vulnerable', False) else "NO"
            status_code = result.get('status_code', 'N/A')
            
            if result['test_type'] == 'Database Reset Access':
                target = result.get('url', 'N/A')
                description = result.get('description', 'N/A')
            elif result['test_type'] == 'User Impersonation':
                target = result.get('url', 'N/A')
                description = result.get('description', 'N/A')
            elif result['test_type'] == 'Sensitive File Access':
                target = result.get('file_name', 'N/A')
                description = result.get('url', 'N/A')
            elif result['test_type'] == 'Form Analysis':
                target = result.get('page', 'N/A')
                description = f"Hidden fields: {result.get('hidden_fields_count', 0)}"
            else:
                target = result.get('test_type', 'N/A')
                description = result.get('description', 'N/A')
            
            # Truncate description if too long
            desc_str = str(description)
            if len(desc_str) > 50:
                desc_display = desc_str[:50] + '...'
            else:
                desc_display = desc_str
            
            html_content += f"""
                <tr>
                    <td>{html.escape(result.get('test_type', 'N/A'))}</td>
                    <td>{html.escape(str(target))}</td>
                    <td>{status_code}</td>
                    <td class="{vulnerable_class}">{vulnerable_text}</td>
                    <td>{html.escape(desc_display)}</td>
                </tr>"""
        
        html_content += """
            </table>"""

        # Add proof of concept for vulnerable attempts
        if self.vulnerable_attempts:
            html_content += """
            <h3>Proof of Concept - Meaningful Access Control Issues</h3>
            <p>The following meaningful access control issues were identified:</p>"""
            
            for i, poc in enumerate(self.vulnerable_attempts[:3]):  # Show first 3 PoCs
                if poc['test_type'] == 'Database Reset Access':
                    poc_details = "Accessed database reset functionality"
                elif poc['test_type'] == 'User Impersonation':
                    poc_details = "Accessed admin user data"
                elif poc['test_type'] == 'Sensitive File Access':
                    poc_details = f"Accessed {poc.get('file_name', 'N/A')}"
                else:
                    poc_details = "Access control issue identified"
                    
                html_content += f"""
            <h4>Access Control Issue {i+1}:</h4>
            <div class="code-block">
<span class="highlight">Issue Type:</span> {html.escape(poc.get('test_type', 'N/A'))}
<span class="highlight">Target:</span> {html.escape(poc_details)}
<span class="highlight">Request:</span> GET {html.escape(poc.get('url', '/'))} HTTP/1.1
<span class="highlight">Authentication:</span> Regular user session (gordonb/abc123)
<span class="highlight">Status Code:</span> {poc.get('status_code', 'N/A')}
<span class="highlight">Result:</span> Successfully accessed restricted functionality
<span class="highlight">Issue:</span> Meaningful Access Control Issue
            </div>"""

        html_content += """
        </div>

        <div class="section">
            <h2>Vulnerability Assessment</h2>
            """
        
        if is_vulnerable:
            html_content += """
            <div class="risk-high">
                <h3>Critical Risk Finding</h3>
                <p>Meaningful access control issues were identified that allow regular users to access sensitive functionality or information. While DVWA doesn't have traditional user roles, these findings represent real security concerns.</p>
            </div>
            
            <h3>Attack Scenarios</h3>
            <ol>
                <li><strong>Database Manipulation:</strong> Access to database reset functionality</li>
                <li><strong>Data Exposure:</strong> Unauthorized access to other user's information</li>
                <li><strong>Configuration Disclosure:</strong> Access to sensitive configuration information</li>
            </ol>
            """
        else:
            html_content += """
            <div class="risk-low">
                <h3>Security Posture</h3>
                <p>The application properly restricts access to sensitive functionality and information. No meaningful access control issues were identified.</p>
            </div>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Important Context and Limitations</h2>
            <div class="disclaimer">
                <h3>Understanding DVWA's Architecture</h3>
                <p>This assessment must be interpreted within the context of DVWA's educational design:</p>
                <ul>
                    <li><strong>No User Roles:</strong> DVWA does not implement traditional user roles or privilege levels beyond authentication status</li>
                    <li><strong>Intentional Accessibility:</strong> Vulnerability testing modules are designed to be accessible by all authenticated users as part of the learning experience</li>
                    <li><strong>Educational Purpose:</strong> DVWA's design prioritizes demonstrating vulnerabilities over implementing production-level access controls</li>
                    <li><strong>Focus on Sensitive Functions:</strong> This testing focused on access to truly sensitive functionality (database reset, configuration files) rather than general application features</li>
                </ul>
                <p><strong>Conclusion:</strong> The findings represent meaningful security issues in the context of access control testing, but must be understood within DVWA's educational framework where traditional privilege escalation is not implemented by design.</p>
            </div>
        </div>

        <div class="section">
            <h2>Conclusion</h2>
            """
        
        if is_vulnerable:
            html_content += """
            <p>The testing revealed meaningful access control issues in DVWA where regular users can access sensitive functionality or information. These findings demonstrate the importance of proper access controls even in educational applications.</p>
            <p>While DVWA does not implement traditional user roles (all authenticated users have the same privileges by design), the ability to access database reset functionality or other users' data represents a meaningful security concern.</p>
            """
        else:
            html_content += """
            <p>The testing found that DVWA properly restricts access to sensitive functionality. No meaningful access control issues were identified, demonstrating good security practices in access control implementation for the truly sensitive functions.</p>
            <p>Note that DVWA's design intentionally makes vulnerability modules accessible to all authenticated users as part of its educational purpose.</p>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <ol>
                <li><strong>Implement Proper Access Controls:</strong> Restrict access to sensitive functionality like database reset</li>
                <li><strong>Data Isolation:</strong> Ensure users can only access their own data where appropriate</li>
                <li><strong>Configuration Protection:</strong> Restrict access to sensitive configuration files</li>
                <li><strong>Regular Security Testing:</strong> Conduct periodic access control testing</li>
            </ol>
        </div>

        <div class="section">
            <h2>Appendices</h2>
            <h3>Tested Sensitive Endpoints</h3>
            <div class="code-block">
/setup.php - Database setup and reset functionality<br>
/vulnerabilities/authbypass/?userid=1 - Admin user data access<br>
/config/config.inc.php - Configuration file<br>
/phpinfo.php - PHP configuration information<br>
            </div>
            
            <h3>References</h3>
            <ul>
                <li><a href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/03-Testing_for_Privilege_Escalation">OWASP Testing Guide - Privilege Escalation (OTG-AUTHZ-003)</a></li>
                <li><a href="https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control">OWASP Top Ten - Broken Access Control</a></li>
                <li><a href="https://www.dvwa.co.uk/">DVWA Documentation</a></li>
            </ul>
        </div>
    </div>
</body>
</html>"""

        # Write report to file
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report generated: {report_filename}")
        return report_filename

    def run_test(self):
        """Run the access control test"""
        print("[*] Starting DVWA Access Control Assessment")
        print(f"[*] Target: {self.base_url}")
        print("[*] Note: DVWA does not implement traditional user roles - all authenticated users have the same privileges")
        
        # Check if target is reachable
        try:
            response = self.session.get(self.base_url, timeout=10)
            if response.status_code != 200:
                print("[-] Target not reachable")
                return False
        except Exception as e:
            print(f"[-] Cannot reach target: {str(e)}")
            return False
        
        # Login as regular user and set security level
        if not self.login_as_regular_user():
            return False
            
        if not self.set_security_level():
            return False
        
        # Perform meaningful access control tests
        self.test_database_reset_access()
        self.test_user_impersonation()
        self.test_configuration_file_access()
        self.test_form_privilege_escalation()
        
        # Generate report
        report_file = self.generate_html_report()
        
        # Print summary
        vulnerable_count = len([r for r in self.test_results if r.get('vulnerable', False)])
        
        print(f"\n[*] Test Summary:")
        print(f"[*] Tests performed: {len(self.test_results)}")
        print(f"[*] Meaningful access control issues found: {vulnerable_count}")
        print(f"[*] Report saved to: {report_file}")
        print("[*] Note: DVWA's design makes vulnerability modules accessible to all authenticated users by design")
        
        if vulnerable_count > 0:
            print("[!] CRITICAL: Meaningful access control issues confirmed!")
        else:
            print("[+] No meaningful access control issues detected.")
        
        return True

if __name__ == "__main__":
    # Create tester instance
    tester = DVWAPrivilegeEscalationTester()
    
    # Run the test
    tester.run_test()