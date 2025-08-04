#!/usr/bin/env python3
"""
DVWA Stack Trace Analysis Script (OTG-ERR-002)
Automated testing for Analysis of Stack Traces on DVWA localhost instance
Generates OSCP-style HTML report with findings
"""

import requests
import re
import time
import os
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urljoin
import sys

class DVWAStackTraceTester:
    def __init__(self, base_url="http://localhost/dvwa"):
        self.base_url = base_url.rstrip('/')  # Remove trailing slash if present
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for localhost
        self.findings = []
        self.report_dir = "./reports"
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def build_url(self, path):
        """Properly build URL by concatenating base URL and path"""
        # Remove leading slash from path if present to avoid absolute path behavior
        if path.startswith('/'):
            path = path[1:]
        return f"{self.base_url}/{path}"

    def login(self, username="admin", password="password"):
        """Login to DVWA and set security level to low"""
        try:
            print("[*] Attempting to login to DVWA...")
            print(f"[*] Base URL: {self.base_url}")
            
            # Get login page to extract CSRF token
            login_url = self.build_url("/login.php")
            print(f"[*] Fetching login page: {login_url}")
            
            response = self.session.get(login_url)
            print(f"[*] Login page status: {response.status_code}")
            
            # Check if we got a valid response
            if response.status_code != 200:
                print(f"[-] Login page returned status {response.status_code}")
                print(f"[*] Response preview: {response.text[:500]}")
                return False
            
            # Debug: Print first 500 chars of response to see what we're getting
            print(f"[*] Response preview: {response.text[:500]}")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try different ways to find the CSRF token
            user_token = None
            
            # Method 1: Standard input field
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input and token_input.get('value'):
                user_token = token_input['value']
                print(f"[+] Found CSRF token (method 1): {user_token[:20]}...")
            
            # Method 2: Hidden input field
            if not user_token:
                hidden_inputs = soup.find_all('input', {'type': 'hidden'})
                for hidden_input in hidden_inputs:
                    if hidden_input.get('name') == 'user_token' and hidden_input.get('value'):
                        user_token = hidden_input['value']
                        print(f"[+] Found CSRF token (method 2): {user_token[:20]}...")
                        break
            
            # Method 3: Any input with user_token name
            if not user_token:
                all_inputs = soup.find_all('input')
                for input_elem in all_inputs:
                    if input_elem.get('name') == 'user_token' and input_elem.get('value'):
                        user_token = input_elem['value']
                        print(f"[+] Found CSRF token (method 3): {user_token[:20]}...")
                        break
            
            login_data = {
                'username': username,
                'password': password,
                'Login': 'Login'
            }
            
            # Add token if found
            if user_token:
                login_data['user_token'] = user_token
                print(f"[*] Including CSRF token in login data")
            else:
                print("[-] No CSRF token found, attempting login without token")
            
            print(f"[*] Login data keys: {list(login_data.keys())}")
            
            # Perform login
            login_response = self.session.post(login_url, data=login_data)
            print(f"[*] Login response status: {login_response.status_code}")
            
            # Check if login was successful
            if "login.php" in login_response.url.lower() or "login failed" in login_response.text.lower():
                print("[-] Login failed - redirecting back to login or showing failure message")
                print(f"[*] Response URL: {login_response.url}")
                # Show more of the response to understand what went wrong
                print(f"[*] Response preview: {login_response.text[:1000]}")
                return False
            
            print("[+] Successfully logged in to DVWA")
            
            # Try to set security level to low
            try:
                security_url = self.build_url("/security.php")
                print(f"[*] Setting security level - accessing: {security_url}")
                sec_response = self.session.get(security_url)
                
                if sec_response.status_code == 200:
                    sec_soup = BeautifulSoup(sec_response.text, 'html.parser')
                    
                    # Find security token
                    sec_token = None
                    sec_token_input = sec_soup.find('input', {'name': 'user_token'})
                    if sec_token_input and sec_token_input.get('value'):
                        sec_token = sec_token_input['value']
                        print(f"[+] Found security CSRF token: {sec_token[:20]}...")
                    
                    if sec_token:
                        security_data = {
                            'security': 'low',
                            'seclev_submit': 'Submit',
                            'user_token': sec_token
                        }
                        
                        sec_post_response = self.session.post(security_url, data=security_data)
                        print("[+] Security level set to Low")
                    else:
                        print("[-] Could not find security CSRF token, skipping security level setting")
                else:
                    print(f"[-] Could not access security page (status: {sec_response.status_code})")
                    
            except Exception as sec_e:
                print(f"[-] Security level setting error (continuing anyway): {sec_e}")
            
            return True
            
        except Exception as e:
            print(f"[-] Login error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def trigger_command_injection(self):
        """Trigger command injection to generate stack traces"""
        print("[*] Testing Command Injection...")
        
        cmd_url = self.build_url("/vulnerabilities/exec/")
        print(f"[*] Command injection URL: {cmd_url}")
        
        try:
            # First check if we can access the page
            response = self.session.get(cmd_url)
            print(f"[*] Command injection page status: {response.status_code}")
            
            if response.status_code == 404:
                print("[-] Command injection page not found. Checking if logged in...")
                # Try to access index to see if we're logged in
                index_url = self.build_url("/index.php")
                index_response = self.session.get(index_url)
                print(f"[*] Index page status: {index_response.status_code}")
                if "login" in index_response.url.lower():
                    print("[-] Not logged in. Cannot access vulnerabilities.")
                    return
                elif response.status_code != 200:
                    print("[-] Command injection module not available in this DVWA version.")
                    return
                    
            if response.status_code != 200:
                print(f"[-] Cannot access command injection page (status: {response.status_code})")
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try to find CSRF token for command injection
            user_token = None
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input and token_input.get('value'):
                user_token = token_input['value']
                print(f"[+] Found command injection CSRF token: {user_token[:20]}...")
            
            # Test payloads that might trigger errors
            payloads = [
                "; phpinfo()",
                "| phpinfo()",
                "&& phpinfo()",
                "'; phpinfo();'",
                "invalid_command_12345_that_does_not_exist"
            ]
            
            for payload in payloads:
                print(f"[*] Testing payload: {payload}")
                
                if user_token:
                    test_data = {
                        'ip': payload,
                        'Submit': 'Submit',
                        'user_token': user_token
                    }
                    response = self.session.post(cmd_url, data=test_data)
                else:
                    # Try without token
                    test_data = {
                        'ip': payload,
                        'Submit': 'Submit'
                    }
                    response = self.session.post(cmd_url, data=test_data)
                
                self.analyze_response(response, "Command Injection", cmd_url, payload)
                time.sleep(1)  # Be respectful to the server
                
        except Exception as e:
            print(f"[-] Command injection test error: {e}")
            import traceback
            traceback.print_exc()

    def trigger_sqli(self):
        """Trigger SQL injection to generate stack traces"""
        print("[*] Testing SQL Injection...")
        
        sqli_url = self.build_url("/vulnerabilities/sqli/")
        print(f"[*] SQL injection URL: {sqli_url}")
        
        try:
            # Check if page exists
            check_response = self.session.get(sqli_url)
            if check_response.status_code == 404:
                print("[-] SQL injection module not found.")
                return
                
            # Test payloads that might trigger database errors
            payloads = [
                "'",
                "\"",
                "1' OR '1'='1",
                "'; DROP TABLE users; --",
                "1 UNION SELECT NULL, version(), NULL --"
            ]
            
            for payload in payloads:
                print(f"[*] Testing SQLi payload: {payload}")
                
                # Test GET parameter
                params = {'id': payload, 'Submit': 'Submit'}
                response = self.session.get(sqli_url, params=params)
                self.analyze_response(response, "SQL Injection (GET)", sqli_url, payload)
                
                # Test POST parameter if applicable
                post_data = {'id': payload, 'Submit': 'Submit'}
                post_response = self.session.post(sqli_url, data=post_data)
                self.analyze_response(post_response, "SQL Injection (POST)", sqli_url, payload)
                
                time.sleep(1)
                
        except Exception as e:
            print(f"[-] SQL injection test error: {e}")
            import traceback
            traceback.print_exc()

    def trigger_xss(self):
        """Trigger XSS to potentially generate errors"""
        print("[*] Testing XSS...")
        
        xss_url = self.build_url("/vulnerabilities/xss_r/")
        print(f"[*] XSS URL: {xss_url}")
        
        try:
            # Check if page exists
            check_response = self.session.get(xss_url)
            if check_response.status_code == 404:
                print("[-] XSS reflected module not found.")
                return
            
            payloads = [
                "<script>phpinfo()</script>",
                "'; phpinfo();'",
                "\"; phpinfo(); //",
                "<?php phpinfo(); ?>",
                "${phpinfo()}"
            ]
            
            for payload in payloads:
                print(f"[*] Testing XSS payload: {payload}")
                params = {'name': payload}
                response = self.session.get(xss_url, params=params)
                self.analyze_response(response, "XSS Reflected", xss_url, payload)
                time.sleep(1)
                
        except Exception as e:
            print(f"[-] XSS test error: {e}")
            import traceback
            traceback.print_exc()

    def trigger_file_upload_errors(self):
        """Trigger file upload errors that might generate stack traces"""
        print("[*] Testing File Upload (for errors)...")
        
        upload_url = self.build_url("/vulnerabilities/upload/")
        print(f"[*] File upload URL: {upload_url}")
        
        try:
            # Check if page exists
            check_response = self.session.get(upload_url)
            if check_response.status_code == 404:
                print("[-] File upload module not found.")
                return
            
            # Try to upload a file with wrong content-type or extension to trigger errors
            files = {
                'uploaded': ('test.txt', b'This is a test file', 'text/plain')
            }
            
            # Try without proper form data first to trigger errors
            response = self.session.post(upload_url, files=files)
            self.analyze_response(response, "File Upload Error", upload_url, "Malformed file upload")
            
        except Exception as e:
            print(f"[-] File upload test error: {e}")

    def analyze_response(self, response, vuln_type, url, payload):
        """Analyze response for stack traces and error messages"""
        content = response.text.lower()
        
        # Common stack trace/error patterns
        error_patterns = [
            r"fatal error.*",
            r"warning.*",
            r"notice.*",
            r"stack trace.*",
            r"call stack.*",
            r"php.*error.*",
            r"mysql.*error.*",
            r"database.*error.*",
            r"uncaught exception.*",
            r"undefined.*",
            r"cannot.*",
            r"failed.*",
            r"mysqli.*exception.*",
            r"pdo.*exception.*",
            r"on line \d+",
            r"in .*\.php on line",
            r"path.*disclosure",
            r"file.*not found"
        ]
        
        found_errors = []
        for pattern in error_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found_errors.extend(matches)
        
        # Also look for full path disclosure
        path_patterns = [
            r"[c-z]:\\.*\.(php|inc|txt|log)",
            r"/(var|usr|home|etc)/.*\.(php|inc|txt|log)",
            r"[c-z]:/.*\.(php|inc|txt|log)"
        ]
        
        for pattern in path_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found_errors.extend(matches)
        
        if found_errors:
            # Extract relevant portion of error for evidence
            error_snippet = ""
            lines = response.text.split('\n')
            for line in lines:
                if any(keyword in line.lower() for keyword in ['fatal', 'warning', 'error', 'stack', 'trace', 'exception', 'undefined', 'cannot', 'failed']):
                    error_snippet = line.strip()[:300]  # First 300 chars
                    break
            
            if not error_snippet and found_errors:
                error_snippet = found_errors[0][:300] if found_errors else "Error detected"
            
            finding = {
                'vulnerability': vuln_type,
                'url': url,
                'payload': payload,
                'status_code': response.status_code,
                'evidence': error_snippet,
                'severity': 'High' if any(word in error_snippet.lower() for word in ['fatal', 'exception']) else 'Medium'
            }
            
            self.findings.append(finding)
            print(f"[+] Found potential stack trace in {vuln_type}: {error_snippet[:100]}...")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTG-ERR-002 - Analysis of Stack Traces - DVWA Assessment</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0a0a23;
            color: #d0d0d0;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #1a1a3a;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
        }}
        h1, h2, h3 {{
            color: #64ffda;
            border-bottom: 2px solid #64ffda;
            padding-bottom: 10px;
        }}
        h1 {{
            text-align: center;
            font-size: 2em;
        }}
        .header-info {{
            background-color: #2a2a4a;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .section {{
            margin-bottom: 30px;
            padding: 15px;
            background-color: #252540;
            border-radius: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #64ffda;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #1e3a5f;
            color: #64ffda;
        }}
        tr:nth-child(even) {{
            background-color: #2d2d50;
        }}
        .code-block {{
            background-color: #1e1e2e;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            margin: 15px 0;
            border-left: 4px solid #64ffda;
            white-space: pre-wrap;
        }}
        .severity-high {{
            color: #ff6b6b;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #ffd93d;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #64ffda;
            color: #888;
        }}
        .executive-summary {{
            background-color: #2a2a4a;
            padding: 20px;
            border-radius: 5px;
            border-left: 5px solid #ff6b6b;
        }}
        .warning {{
            background-color: #3a2a2a;
            border-left: 5px solid #ff6b6b;
            padding: 15px;
            margin: 15px 0;
            border-radius: 3px;
        }}
        .info {{
            background-color: #2a3a3a;
            border-left: 5px solid #64ffda;
            padding: 15px;
            margin: 15px 0;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>OTG-ERR-002 - Analysis of Stack Traces</h1>
        <h1>DVWA Localhost Assessment</h1>
        
        <div class="header-info">
            <p><strong>Test Date:</strong> {timestamp}</p>
            <p><strong>Target:</strong> {self.base_url}</p>
            <p><strong>Tester:</strong> AI Security Agent</p>
            <p><strong>OWASP Test ID:</strong> OTG-ERR-002</p>
        </div>

        <div class="section">
            <h2>1. Executive Summary</h2>
            <div class="executive-summary">
                <p>This assessment focused on identifying stack traces and error messages exposed by the Damn Vulnerable Web App (DVWA) when processing malformed input. Stack traces can reveal critical information about the application's internal structure, including file paths, function names, variable values, and server configurations.</p>
"""

        if self.findings:
            html_content += f"""
                <p>The testing revealed {len(self.findings)} instances where detailed error messages were displayed to users, potentially aiding attackers in understanding the application's architecture and identifying further attack vectors.</p>
"""
        else:
            html_content += """
                <p>The testing did not reveal any obvious stack traces or detailed error messages being exposed to users. This indicates good security practices regarding error handling in this DVWA instance.</p>
"""

        html_content += """
            </div>
        </div>

        <div class="section">
            <h2>2. Test Details</h2>
            <p><strong>OWASP Test ID:</strong> OTG-ERR-002 - Analysis of Stack Traces</p>
            <p><strong>Test Objective:</strong> Identify system or application stack traces that may be exposed to users through error messages, which could provide valuable information to attackers.</p>
            <p><strong>Risk Description:</strong> Stack traces can reveal:</p>
            <ul>
                <li>Application framework and version information</li>
                <li>File system paths and directory structures</li>
                <li>Database schema and query structures</li>
                <li>Variable names and values at runtime</li>
                <li>Server configuration details</li>
            </ul>
        </div>

        <div class="section">
            <h2>3. Methodology</h2>
            <p><strong>Tools Used:</strong> Custom Python script utilizing requests and BeautifulSoup libraries</p>
            <p><strong>Testing Approach:</strong></p>
            <ol>
                <li>Attempted authentication to DVWA with default credentials</li>
                <li>Set security level to "Low" when possible</li>
                <li>Targeted vulnerable modules: Command Injection, SQL Injection, XSS, and File Upload</li>
                <li>Injected malformed inputs designed to trigger error conditions</li>
                <li>Analyzed HTTP responses for stack traces and error messages</li>
                <li>Documented findings with evidence and severity assessment</li>
            </ol>
        </div>

        <div class="section">
            <h2>4. Findings</h2>
"""

        if not self.findings:
            html_content += """
            <div class="info">
                <p><strong>No stack traces or detailed error messages were found during testing.</strong></p>
                <p>This is a positive security finding, indicating that:</p>
                <ul>
                    <li>Error display is likely properly disabled in the PHP configuration</li>
                    <li>The DVWA instance appears to be configured with secure error handling</li>
                    <li>Detailed system information is not being exposed to end users</li>
                </ul>
                <p>However, the absence of visible errors does not guarantee that detailed error information is not being logged or that other error handling vulnerabilities don't exist.</p>
            </div>
"""
        else:
            html_content += """
            <table>
                <tr>
                    <th>Vulnerability</th>
                    <th>URL</th>
                    <th>Payload</th>
                    <th>Status</th>
                    <th>Evidence</th>
                    <th>Severity</th>
                </tr>
"""

            # Add findings to table
            for finding in self.findings:
                severity_class = "severity-high" if finding['severity'] == "High" else "severity-medium"
                # Escape HTML in evidence
                escaped_evidence = finding['evidence'].replace('<', '<').replace('>', '>')
                html_content += f"""
                <tr>
                    <td>{finding['vulnerability']}</td>
                    <td>{finding['url']}</td>
                    <td>{finding['payload']}</td>
                    <td>{finding['status_code']}</td>
                    <td>{escaped_evidence}</td>
                    <td class="{severity_class}">{finding['severity']}</td>
                </tr>
"""

            html_content += """
            </table>
        </div>

        <div class="section">
            <h2>5. Evidence Snippets</h2>
"""

            # Add detailed evidence
            for i, finding in enumerate(self.findings, 1):
                escaped_evidence = finding['evidence'].replace('<', '<').replace('>', '>')
                html_content += f"""
            <h3>5.{i} {finding['vulnerability']} - {finding['severity']} Severity</h3>
            <p><strong>URL:</strong> {finding['url']}</p>
            <p><strong>Payload:</strong> {finding['payload']}</p>
            <div class="code-block">
{escaped_evidence}
            </div>
"""

        html_content += """
        </div>

        <div class="section">
            <h2>6. Remediation Recommendations</h2>
            <p>Even though no issues were found, here are general best practices for error handling:</p>
            <ol>
                <li><strong>Disable Error Display:</strong> Set display_errors = Off in php.ini for production environments</li>
                <li><strong>Custom Error Pages:</strong> Implement custom error pages that don't expose system information</li>
                <li><strong>Error Logging:</strong> Log errors to secure files instead of displaying them to users</li>
                <li><strong>Input Validation:</strong> Implement strict input validation and sanitization</li>
                <li><strong>Security Headers:</strong> Implement proper security headers to prevent information leakage</li>
                <li><strong>Regular Testing:</strong> Conduct regular security assessments to identify exposed error messages</li>
            </ol>
        </div>

        <div class="section">
            <h2>7. Conclusion</h2>
"""

        if self.findings:
            html_content += f"""
            <p>The DVWA instance running on localhost was found to expose detailed stack traces and error messages when processing malformed input. These {len(self.findings)} error messages provide attackers with valuable information about the application's internal structure and could be used to facilitate further attacks.</p>
            <p>Immediate remediation is recommended to prevent information disclosure through proper error handling and configuration management.</p>
"""
        else:
            html_content += """
            <p>The DVWA instance running on localhost did not expose detailed stack traces or error messages during this assessment. This indicates good security practices regarding error handling. The application appears to be configured to prevent information disclosure through error messages.</p>
            <p>This is a positive security finding, demonstrating that the application follows secure error handling practices that do not expose internal system information to end users.</p>
"""

        html_content += f"""
        </div>

        <div class="footer">
            <p>Generated on {timestamp} by AI Security Agent</p>
            <p>OWASP Testing Guide v4.2 - OTG-ERR-002</p>
        </div>
    </div>
</body>
</html>
"""

        # Write report to file
        report_path = os.path.join(self.report_dir, "OTG-ERR-002_Stack_Trace_Report.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report generated: {report_path}")
        return report_path

    def run_assessment(self):
        """Run the complete stack trace analysis assessment"""
        print("[*] Starting DVWA Stack Trace Analysis (OTG-ERR-002)")
        print(f"[*] Target: {self.base_url}")
        
        # Login to DVWA
        if not self.login():
            print("[-] Failed to login to DVWA. Attempting tests without authentication...")
            # Check if we can access the main page to see if we're already logged in
            try:
                index_url = self.build_url("/index.php")
                index_response = self.session.get(index_url)
                if "login" not in index_response.url.lower() and index_response.status_code == 200:
                    print("[+] Appears to be already logged in or no authentication required")
                else:
                    print("[-] Not logged in and cannot access protected areas")
            except:
                pass
        else:
            print("[+] Successfully authenticated to DVWA")
        
        # Run tests
        print("[*] Running vulnerability tests...")
        self.trigger_command_injection()
        self.trigger_sqli()
        self.trigger_xss()
        self.trigger_file_upload_errors()
        
        # Generate report
        print(f"[*] Generating report with {len(self.findings)} findings...")
        self.generate_html_report()

def main():
    """Main function to run the stack trace analyzer"""
    # Allow command line argument to specify base URL
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
        tester = DVWAStackTraceTester(base_url=base_url)
    else:
        # Default to DVWA in subdirectory
        tester = DVWAStackTraceTester(base_url="http://localhost/dvwa")
    tester.run_assessment()

if __name__ == "__main__":
    main()