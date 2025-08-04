#!/usr/bin/env python3
"""
DVWA Cross-Origin Resource Sharing (OTG-CLIENT-007) Test Script
Author: AI Security Agent
Description: Diagnostic testing for CORS configuration in DVWA
Note: DVWA does not implement CORS-based APIs, so this is a header analysis only
"""

import requests
from bs4 import BeautifulSoup
import logging
from datetime import datetime
import html

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWACORSChecker:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.endpoints = [
            "/",
            "/login.php",
            "/security.php",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/xss_s/",
            "/vulnerabilities/sqli/",
            "/vulnerabilities/csrf/"
        ]
        self.findings = []
        self.cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Credentials',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Expose-Headers',
            'Access-Control-Max-Age'
        ]

    def login_to_dvwa(self):
        """Login to DVWA with default credentials"""
        try:
            # Get login page
            response = self.session.get(f"{self.base_url}/login.php")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract user token
            user_token_input = soup.find('input', {'name': 'user_token'})
            if user_token_input and user_token_input.get('value'):
                user_token = user_token_input['value']
                logger.info(f"Extracted user token: {user_token}")
            else:
                logger.error("Could not find user token in login page")
                return False
            
            # Login data
            login_data = {
                'username': 'admin',
                'password': 'password',
                'user_token': user_token,
                'Login': 'Login'
            }
            
            # Perform login
            login_response = self.session.post(f"{self.base_url}/login.php", data=login_data)
            
            if "Welcome :: Damn Vulnerable Web Application" in login_response.text:
                logger.info("Successfully logged into DVWA")
                return True
            else:
                logger.error("Failed to login to DVWA")
                return False
                
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return False

    def check_cors_headers(self, url):
        """Check CORS headers on a given URL"""
        try:
            # Test GET request with custom Origin header
            get_headers = {'Origin': 'https://evil.com'}
            get_response = self.session.get(url, headers=get_headers)
            
            # Test OPTIONS request (preflight) with custom Origin header
            options_headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'X-Requested-With'
            }
            options_response = self.session.options(url, headers=options_headers)
            
            # Extract CORS headers from both responses
            cors_data = {
                'url': url,
                'get_headers': {},
                'options_headers': {},
                'vulnerable': False,
                'issues': []
            }
            
            # Check GET response
            for header in self.cors_headers:
                value = get_response.headers.get(header)
                if value:
                    cors_data['get_headers'][header] = value
                    
            # Check OPTIONS response
            for header in self.cors_headers:
                value = options_response.headers.get(header)
                if value:
                    cors_data['options_headers'][header] = value
            
            # Analyze for vulnerabilities
            get_origin = get_response.headers.get('Access-Control-Allow-Origin', '')
            options_origin = options_response.headers.get('Access-Control-Allow-Origin', '')
            get_credentials = get_response.headers.get('Access-Control-Allow-Credentials', '')
            options_credentials = options_response.headers.get('Access-Control-Allow-Credentials', '')
            
            # Check for origin reflection
            if 'https://evil.com' in get_origin or 'https://evil.com' in options_origin:
                cors_data['vulnerable'] = True
                cors_data['issues'].append("Origin reflection detected")
            
            # Check for dangerous wildcard + credentials combination
            if (get_origin == '*' and get_credentials == 'true') or (options_origin == '*' and options_credentials == 'true'):
                cors_data['vulnerable'] = True
                cors_data['issues'].append("Wildcard origin with credentials allowed")
            
            self.findings.append(cors_data)
            logger.info(f"Checked CORS headers for {url}")
            
        except Exception as e:
            logger.error(f"Error checking CORS headers for {url}: {e}")

    def run_scan(self):
        """Scan all DVWA endpoints for CORS headers"""
        logger.info("Starting CORS header analysis for DVWA endpoints...")
        
        for endpoint in self.endpoints:
            url = f"{self.base_url}{endpoint}"
            self.check_cors_headers(url)

    def analyze_findings(self):
        """Analyze findings for overall security posture"""
        total_endpoints = len(self.findings)
        endpoints_with_cors = 0
        vulnerable_endpoints = 0
        
        for finding in self.findings:
            if finding['get_headers'] or finding['options_headers']:
                endpoints_with_cors += 1
            if finding['vulnerable']:
                vulnerable_endpoints += 1
        
        return {
            'total_endpoints': total_endpoints,
            'endpoints_with_cors': endpoints_with_cors,
            'vulnerable_endpoints': vulnerable_endpoints
        }

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        analysis = self.analyze_findings()
        
        # Generate findings HTML
        findings_html = ""
        for finding in self.findings:
            url = html.escape(finding['url'])
            get_headers_text = ""
            options_headers_text = ""
            
            for header, value in finding['get_headers'].items():
                get_headers_text += f"  {html.escape(header)}: {html.escape(value)}\n"
            
            for header, value in finding['options_headers'].items():
                options_headers_text += f"  {html.escape(header)}: {html.escape(value)}\n"
            
            issues_text = "\n".join([html.escape(issue) for issue in finding['issues']]) if finding['issues'] else "None"
            
            findings_html += f"""
            <h3>{url}</h3>
            <pre>
GET Response Headers:
{html.escape(get_headers_text) if get_headers_text else '  No CORS headers found'}

OPTIONS Response Headers:
{html.escape(options_headers_text) if options_headers_text else '  No CORS headers found'}

Security Issues:
{issues_text}
            </pre>
            """

        # Determine overall status
        if analysis['vulnerable_endpoints'] > 0:
            overall_status = '<span class="vulnerable">Vulnerable</span>'
        elif analysis['endpoints_with_cors'] > 0:
            overall_status = '<span class="info">CORS Headers Present (Not Vulnerable)</span>'
        else:
            overall_status = '<span class="safe">Not Vulnerable (No CORS Exposure)</span>'

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>OSCP-Style Security Assessment Report</title>
  <style>
    /* OSCP-inspired styling: monospace, dark theme, clean layout */
    body {{ 
      font-family: 'Courier New', monospace; 
      background: #111; 
      color: #00FF00; 
      padding: 20px; 
      line-height: 1.6;
    }}
    .header {{ text-align: center; margin-bottom: 30px; }}
    h1, h2, h3 {{ color: #00CCFF; border-bottom: 1px solid #00CCFF; padding-bottom: 5px; }}
    .section {{ margin: 20px 0; }}
    pre {{ 
      background: #222; 
      padding: 12px; 
      border-left: 5px solid #00CCFF; 
      overflow-x: auto; 
      font-size: 0.9em;
      color: #FFCC00;
    }}
    .evidence {{ color: #FFCC00; font-weight: bold; }}
    .recommendation {{ color: #AAFF00; }}
    .vulnerable {{ color: #FF5555; font-weight: bold; }}
    .safe {{ color: #55FF55; }}
    .info {{ color: #55AAFF; }}
    footer {{ margin-top: 60px; font-size: 0.8em; text-align: center; color: #666; }}
    code {{ background: #333; padding: 2px 4px; border-radius: 3px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Test ID:</strong> OTG-CLIENT-007</p>
    <p><strong>Vulnerability:</strong> Cross-Origin Resource Sharing (CORS)</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Analyze the application for misconfigured CORS policies that could allow unauthorized domains to access sensitive data.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-007</p>
    <p><strong>Note:</strong> DVWA is a traditional PHP application with no AJAX-based APIs. Therefore, <strong>no actual CORS exploitation is possible</strong>. This test checks for header presence and educational completeness.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Send <code>GET</code> and <code>OPTIONS</code> requests to key endpoints.</p>
    <p>3. Include custom <code>Origin: https://evil.com</code> header to test for reflection.</p>
    <p>4. Extract and analyze CORS-related HTTP response headers.</p>
    <p>5. Document findings and security posture.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>CORS Header Analysis</h3>
    <p><strong>Status:</strong> {overall_status}</p>
    <p><strong>Endpoints Scanned:</strong> {analysis['total_endpoints']}</p>
    <p><strong>Endpoints with CORS Headers:</strong> {analysis['endpoints_with_cors']}</p>
    <p><strong>Vulnerable Endpoints:</strong> {analysis['vulnerable_endpoints']}</p>
    {findings_html}
    <p class="evidence"><strong>Evidence:</strong> {'CORS misconfigurations detected that could allow cross-origin data access.' if analysis['vulnerable_endpoints'] > 0 else 'No CORS headers were found on any tested endpoints. The application does not expose cross-origin resource sharing.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>Since DVWA does not implement CORS-based APIs or AJAX interactions, there is no risk of cross-origin data leakage via XHR/fetch. However, this also means DVWA cannot be used to practice real-world CORS vulnerability testing. The absence of CORS headers is actually the secure configuration for a traditional server-rendered application like DVWA.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- If implementing APIs, avoid using <code>Access-Control-Allow-Origin: *</code> with <code>Access-Control-Allow-Credentials: true</code>.</p>
    <p class="recommendation">- Whitelist specific origins instead of echoing the <code>Origin</code> header.</p>
    <p class="recommendation">- Validate and sanitize all CORS-related headers on the server side.</p>
    <p class="recommendation">- For learning CORS exploitation, use platforms like WebGoat, Juice Shop, or PortSwigger Academy.</p>
    <p class="recommendation">- Regularly audit API endpoints for CORS misconfigurations in modern web applications.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-007_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-007_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA CORS Analysis (OTG-CLIENT-007)")
            
            # Login to DVWA
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            # Run CORS header analysis
            self.run_scan()
            
            # Generate report
            self.generate_html_report()
            
            logger.info("CORS analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during testing: {e}")

if __name__ == "__main__":
    checker = DVWACORSChecker()
    checker.run_tests()