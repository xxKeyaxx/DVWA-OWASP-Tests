#!/usr/bin/env python3
"""
DVWA WebSockets (OTG-CLIENT-010) Test Script
Author: AI Security Agent
Description: Diagnostic testing for WebSocket functionality in DVWA
Note: DVWA does not implement WebSockets - this is a compliance check
"""

import requests
from bs4 import BeautifulSoup
import logging
from datetime import datetime
import html
import re
try:
    import websockets
    import asyncio
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    logging.info("websockets library not available - WebSocket connection testing will be skipped")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWAWebSocketChecker:
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
        self.websocket_indicators = {
            'websocket_calls': [],
            'websocket_handlers': [],
            'websocket_strings': [],
            'websocket_libraries': [],
            'upgrade_headers': []
        }

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

    def check_for_websocket_content(self, url):
        """Check for WebSocket content in a given URL"""
        try:
            response = self.session.get(url)
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            
            finding = {
                'url': url,
                'websocket_call_count': 0,
                'handler_count': 0,
                'string_count': 0,
                'library_count': 0,
                'upgrade_header': False,
                'details': []
            }
            
            # Check for WebSocket constructor calls
            websocket_patterns = [
                r'new\s+WebSocket\s*\(',
                r'new\s+ReconnectingWebSocket\s*\(',
                r'io\s*\(\s*[\'"]ws',
                r'Socket\s*\.\s*connect'
            ]
            
            websocket_call_count = 0
            for pattern in websocket_patterns:
                matches = re.findall(pattern, content, re.I)
                websocket_call_count += len(matches)
            
            finding['websocket_call_count'] = websocket_call_count
            if websocket_call_count > 0:
                self.websocket_indicators['websocket_calls'].append(url)
                finding['details'].append(f"Found {websocket_call_count} WebSocket constructor calls")
            
            # Check for WebSocket event handlers
            handler_patterns = [
                r'\.\s*onmessage\s*=',
                r'\.\s*onopen\s*=',
                r'\.\s*onerror\s*=',
                r'\.\s*onclose\s*=',
                r'addEventListener\s*\(\s*[\'"]message[\'"]',
                r'addEventListener\s*\(\s*[\'"]open[\'"]'
            ]
            
            handler_count = 0
            for pattern in handler_patterns:
                matches = re.findall(pattern, content, re.I)
                handler_count += len(matches)
            
            finding['handler_count'] = handler_count
            if handler_count > 0:
                self.websocket_indicators['websocket_handlers'].append(url)
                finding['details'].append(f"Found {handler_count} WebSocket event handlers")
            
            # Check for WebSocket-related strings
            string_patterns = [
                r'ws://',
                r'wss://',
                r'websocket',
                r'socket\.send\s*\(',
                r'socket\.emit\s*\('
            ]
            
            string_count = 0
            for pattern in string_patterns:
                matches = re.findall(pattern, content, re.I)
                string_count += len(matches)
            
            finding['string_count'] = string_count
            if string_count > 0:
                self.websocket_indicators['websocket_strings'].append(url)
                finding['details'].append(f"Found {string_count} WebSocket-related strings")
            
            # Check for WebSocket libraries
            library_patterns = [
                r'socket\.io',
                r'sockjs',
                r'engine\.io',
                r'faye',
                r'primus'
            ]
            
            library_count = 0
            for pattern in library_patterns:
                matches = re.findall(pattern, content, re.I)
                library_count += len(matches)
            
            finding['library_count'] = library_count
            if library_count > 0:
                self.websocket_indicators['websocket_libraries'].append(url)
                finding['details'].append(f"Found {library_count} WebSocket library references")
            
            # Check for WebSocket upgrade headers in response
            upgrade_header = response.headers.get('Upgrade', '').lower()
            if 'websocket' in upgrade_header:
                finding['upgrade_header'] = True
                self.websocket_indicators['upgrade_headers'].append(url)
                finding['details'].append("Found WebSocket Upgrade header in response")
            
            # Add to findings if any WebSocket content found
            if any([
                finding['websocket_call_count'] > 0,
                finding['handler_count'] > 0,
                finding['string_count'] > 0,
                finding['library_count'] > 0,
                finding['upgrade_header']
            ]):
                self.findings.append(finding)
                logger.warning(f"WebSocket content found in {url}")
            else:
                logger.info(f"No WebSocket content found in {url}")
                
        except Exception as e:
            logger.error(f"Error checking {url}: {e}")

    def check_javascript_files(self):
        """Check linked JavaScript files for WebSocket content"""
        try:
            for endpoint in self.endpoints:
                url = f"{self.base_url}{endpoint}"
                response = self.session.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all script tags with src
                script_tags = soup.find_all('script', src=True)
                
                for script_tag in script_tags:
                    script_src = script_tag['src']
                    # Handle relative URLs
                    if script_src.startswith('/'):
                        script_url = f"{self.base_url}{script_src}"
                    elif script_src.startswith('http'):
                        script_url = script_src
                    else:
                        script_url = f"{self.base_url}/{script_src}"
                    
                    try:
                        script_response = self.session.get(script_url)
                        script_content = script_response.text
                        
                        # Check for WebSocket-related content in JavaScript
                        websocket_patterns = [
                            'new WebSocket', 'onmessage', 'socket.send', 
                            'socket.emit', 'socket.io', 'ws://', 'wss://'
                        ]
                        
                        found_patterns = []
                        for pattern in websocket_patterns:
                            if pattern.lower() in script_content.lower():
                                found_patterns.append(pattern)
                        
                        if found_patterns:
                            logger.info(f"WebSocket-related content found in JavaScript: {script_url}")
                            logger.info(f"Patterns found: {found_patterns}")
                            
                    except Exception as e:
                        logger.debug(f"Could not fetch script {script_url}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error checking JavaScript files: {e}")

    def test_websocket_connections(self):
        """Test for WebSocket servers on common ports"""
        if not WEBSOCKETS_AVAILABLE:
            logger.info("Skipping WebSocket connection testing - websockets library not available")
            return
            
        common_ws_endpoints = [
            "ws://localhost:8080",
            "ws://localhost:3000",
            "ws://localhost:8000",
            "ws://127.0.0.1:8080",
            "wss://localhost:8443"
        ]
        
        async def test_single_connection(ws_url):
            try:
                async with websockets.connect(ws_url, timeout=5):
                    logger.info(f"Successfully connected to WebSocket server: {ws_url}")
                    return True
            except Exception as e:
                logger.debug(f"Could not connect to WebSocket server {ws_url}: {e}")
                return False
        
        async def test_all_connections():
            tasks = [test_single_connection(url) for url in common_ws_endpoints]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            connected_endpoints = [common_ws_endpoints[i] for i, result in enumerate(results) if result is True]
            return connected_endpoints
        
        try:
            logger.info("Testing for WebSocket servers on common ports...")
            connected = asyncio.run(test_all_connections())
            
            if connected:
                logger.warning(f"Found WebSocket servers: {connected}")
                # Add to findings
                finding = {
                    'url': 'External WebSocket Servers',
                    'websocket_call_count': 0,
                    'handler_count': 0,
                    'string_count': 0,
                    'library_count': 0,
                    'upgrade_header': False,
                    'details': [f"Connected to WebSocket servers: {', '.join(connected)}"]
                }
                self.findings.append(finding)
            else:
                logger.info("No WebSocket servers found on common ports")
                
        except Exception as e:
            logger.error(f"Error testing WebSocket connections: {e}")

    def run_scan(self):
        """Scan all DVWA endpoints for WebSocket content"""
        logger.info("Starting WebSocket analysis for DVWA endpoints...")
        
        for endpoint in self.endpoints:
            url = f"{self.base_url}{endpoint}"
            self.check_for_websocket_content(url)
        
        # Check JavaScript files
        logger.info("Checking JavaScript files for WebSocket content...")
        self.check_javascript_files()
        
        # Test WebSocket connections
        self.test_websocket_connections()

    def analyze_findings(self):
        """Analyze findings for overall security posture"""
        total_endpoints = len(self.endpoints)
        endpoints_with_websocket = len(self.findings)
        
        return {
            'total_endpoints': total_endpoints,
            'endpoints_with_websocket': endpoints_with_websocket,
            'websocket_indicators': self.websocket_indicators
        }

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        analysis = self.analyze_findings()
        
        # Generate findings HTML
        findings_html = ""
        if self.findings:
            for finding in self.findings:
                url = html.escape(finding['url'])
                details = "\n".join([html.escape(detail) for detail in finding['details']]) if finding['details'] else "No specific details"
                
                findings_html += f"""
                <h3>{url}</h3>
                <pre>
WebSocket Constructor Calls: {finding['websocket_call_count']}
Event Handlers: {finding['handler_count']}
WebSocket Strings: {finding['string_count']}
Library References: {finding['library_count']}
Upgrade Header: {'Yes' if finding['upgrade_header'] else 'No'}

Details:
{details}
                </pre>
                """
        else:
            findings_html = "<p>No WebSocket functionality was found in any scanned endpoints.</p>"

        # Determine overall status
        if analysis['endpoints_with_websocket'] > 0:
            overall_status = '<span class="info">WebSocket Content Found (Review Required)</span>'
        else:
            overall_status = '<span class="safe">Not Applicable (WebSockets Not Used)</span>'

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
    .safe {{ color: #55FF55; }}
    .info {{ color: #55AAFF; }}
    footer {{ margin-top: 60px; font-size: 0.8em; text-align: center; color: #666; }}
    code {{ background: #333; padding: 2px 4px; border-radius: 3px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Test ID:</strong> OTG-CLIENT-010</p>
    <p><strong>Vulnerability:</strong> WebSockets Security</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Determine if the application uses WebSockets for real-time communication.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-010</p>
    <p><strong>Note:</strong> DVWA is a traditional server-rendered PHP application without real-time features. This test confirms the absence of WebSocket implementation.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Scan all pages for WebSocket-related JavaScript code.</p>
    <p>3. Analyze HTTP headers for WebSocket upgrade attempts.</p>
    <p>4. Attempt to connect to common WebSocket ports.</p>
    <p>5. Confirm no WebSocket functionality is present.</p>
    <p>6. Document findings and security posture.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>WebSocket Implementation</h3>
    <p><strong>Status:</strong> {overall_status}</p>
    <p><strong>Endpoints Scanned:</strong> {analysis['total_endpoints']}</p>
    <p><strong>Endpoints with WebSocket Content:</strong> {analysis['endpoints_with_websocket']}</p>
    {findings_html}
    <p class="evidence"><strong>Evidence:</strong> {'WebSocket functionality was detected and should be reviewed.' if analysis['endpoints_with_websocket'] > 0 else 'No WebSocket functionality was found in DVWA. The application uses traditional request-response patterns without real-time communication.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>Since DVWA does not use WebSockets, there is no risk of WebSocket-specific vulnerabilities such as message injection, authentication bypass, or cross-site WebSocket hijacking. However, this also means DVWA cannot be used to practice real-world WebSocket security testing.</p>
    <p><strong>Educational Context:</strong> WebSockets enable bidirectional, real-time communication between clients and servers. While powerful, they introduce security risks including:</p>
    <ul>
      <li>Cross-Site WebSocket Hijacking (CSWSH)</li>
      <li>Message injection and manipulation</li>
      <li>Insecure authentication and authorization</li>
      <li>Denial of Service through connection flooding</li>
      <li>Data leakage through improper message handling</li>
    </ul>
    <p>Modern applications using WebSockets should implement proper origin validation, authentication, and message sanitization.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- For applications requiring real-time features, implement WebSockets securely.</p>
    <p class="recommendation">- Validate and sanitize all WebSocket messages on the server side.</p>
    <p class="recommendation">- Implement proper authentication and authorization for WebSocket connections.</p>
    <p class="recommendation">- Use WSS (WebSocket Secure) instead of WS for encrypted communication.</p>
    <p class="recommendation">- Protect against Cross-Site WebSocket Hijacking (CSWSH) with origin validation.</p>
    <p class="recommendation">- Implement rate limiting and connection management to prevent DoS attacks.</p>
    <p class="recommendation">- For learning WebSocket security, use platforms like WebGoat or Juice Shop.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-010_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-010_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA WebSocket Analysis (OTG-CLIENT-010)")
            
            # Login to DVWA
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            # Run WebSocket content analysis
            self.run_scan()
            
            # Generate report
            self.generate_html_report()
            
            # Final summary
            if self.findings:
                logger.warning(f"⚠️  WebSocket content detected in {len(self.findings)} endpoints!")
            else:
                logger.info("✅ No WebSocket functionality found in DVWA")
                logger.info("ℹ️  This is expected as DVWA is a traditional PHP application without real-time features.")
            
            logger.info("WebSocket analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during testing: {e}")

if __name__ == "__main__":
    checker = DVWAWebSocketChecker()
    checker.run_tests()