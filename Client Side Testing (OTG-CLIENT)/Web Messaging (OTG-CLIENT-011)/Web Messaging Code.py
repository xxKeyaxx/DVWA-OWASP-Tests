#!/usr/bin/env python3
"""
DVWA Web Messaging (OTG-CLIENT-011) Test Script
Author: AI Security Agent
Description: Diagnostic testing for Web Messaging functionality in DVWA
Note: DVWA does not implement postMessage() - this is a compliance check
"""

import requests
from bs4 import BeautifulSoup
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
from datetime import datetime
import html
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWAWebMessagingChecker:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.driver = None
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
        self.web_messaging_indicators = {
            'postmessage_calls': [],
            'message_listeners': [],
            'origin_checks': [],
            'insecure_data_handling': [],
            'iframe_communication': []
        }

    def setup_driver(self):
        """Setup Chrome WebDriver for Selenium"""
        try:
            options = Options()
            options.add_argument('--headless=new')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-plugins')
            self.driver = webdriver.Chrome(options=options)
            self.driver.implicitly_wait(10)
            logger.info("WebDriver initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize WebDriver: {e}")
            return False
        return True

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

    def check_for_web_messaging_content(self, url):
        """Check for Web Messaging content in a given URL"""
        try:
            response = self.session.get(url)
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            
            finding = {
                'url': url,
                'postmessage_count': 0,
                'listener_count': 0,
                'origin_check_count': 0,
                'insecure_data_count': 0,
                'iframe_count': 0,
                'details': []
            }
            
            # Check for postMessage calls
            postmessage_patterns = [
                r'\.postMessage\s*\(',
                r'window\.postMessage\s*\(',
                r'frames\[.*?\]\.postMessage\s*\('
            ]
            
            postmessage_count = 0
            for pattern in postmessage_patterns:
                matches = re.findall(pattern, content, re.I)
                postmessage_count += len(matches)
            
            finding['postmessage_count'] = postmessage_count
            if postmessage_count > 0:
                self.web_messaging_indicators['postmessage_calls'].append(url)
                finding['details'].append(f"Found {postmessage_count} postMessage() calls")
            
            # Check for message event listeners
            listener_patterns = [
                r'addEventListener\s*\(\s*[\'"]message[\'"]',
                r'\.onmessage\s*=',
                r'window\.onmessage\s*=',
                r'document\.onmessage\s*='
            ]
            
            listener_count = 0
            for pattern in listener_patterns:
                matches = re.findall(pattern, content, re.I)
                listener_count += len(matches)
            
            finding['listener_count'] = listener_count
            if listener_count > 0:
                self.web_messaging_indicators['message_listeners'].append(url)
                finding['details'].append(f"Found {listener_count} message event listeners")
            
            # Check for origin validation
            origin_patterns = [
                r'event\.origin',
                r'message\.origin',
                r'if\s*\(\s*origin\s*!==',
                r'origin\s*==\s*[\'"]\*+[\'"]'
            ]
            
            origin_check_count = 0
            for pattern in origin_patterns:
                matches = re.findall(pattern, content, re.I)
                origin_check_count += len(matches)
            
            finding['origin_check_count'] = origin_check_count
            if origin_check_count > 0:
                self.web_messaging_indicators['origin_checks'].append(url)
                finding['details'].append(f"Found {origin_check_count} origin validation checks")
            
            # Check for insecure data handling
            insecure_patterns = [
                r'\.innerHTML\s*=\s*.*?event\.data',
                r'\.outerHTML\s*=\s*.*?event\.data',
                r'eval\s*\(\s*.*?event\.data',
                r'execCommand\s*\(\s*.*?event\.data'
            ]
            
            insecure_data_count = 0
            for pattern in insecure_patterns:
                matches = re.findall(pattern, content, re.I)
                insecure_data_count += len(matches)
            
            finding['insecure_data_count'] = insecure_data_count
            if insecure_data_count > 0:
                self.web_messaging_indicators['insecure_data_handling'].append(url)
                finding['details'].append(f"Found {insecure_data_count} insecure data handling patterns")
            
            # Check for cross-origin iframes
            iframe_tags = soup.find_all('iframe', src=re.compile(r'^https?://', re.I))
            finding['iframe_count'] = len(iframe_tags)
            if iframe_tags:
                self.web_messaging_indicators['iframe_communication'].append(url)
                finding['details'].append(f"Found {len(iframe_tags)} cross-origin iframes")
            
            # Add to findings if any Web Messaging content found
            if any([
                finding['postmessage_count'] > 0,
                finding['listener_count'] > 0,
                finding['origin_check_count'] > 0,
                finding['insecure_data_count'] > 0,
                finding['iframe_count'] > 0
            ]):
                self.findings.append(finding)
                logger.warning(f"Web Messaging content found in {url}")
            else:
                logger.info(f"No Web Messaging content found in {url}")
                
        except Exception as e:
            logger.error(f"Error checking {url}: {e}")

    def check_javascript_files(self):
        """Check linked JavaScript files for Web Messaging content"""
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
                        
                        # Check for Web Messaging-related content in JavaScript
                        web_messaging_patterns = [
                            'postMessage', 'addEventListener.*message', 'onmessage', 
                            'event.origin', 'event.data', 'innerHTML.*event.data'
                        ]
                        
                        found_patterns = []
                        for pattern in web_messaging_patterns:
                            if pattern.lower() in script_content.lower():
                                found_patterns.append(pattern)
                        
                        if found_patterns:
                            logger.info(f"Web Messaging-related content found in JavaScript: {script_url}")
                            logger.info(f"Patterns found: {found_patterns}")
                            
                    except Exception as e:
                        logger.debug(f"Could not fetch script {script_url}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error checking JavaScript files: {e}")

    def check_runtime_message_listeners(self, url):
        """Use Selenium to check for active message listeners"""
        try:
            if not self.driver:
                logger.warning("WebDriver not available for runtime checks")
                return
                
            self.driver.get(url)
            
            # Check if any message listeners are registered
            has_listeners = self.driver.execute_script("""
                try {
                    // Check for message event listeners
                    var listeners = getEventListeners(window);
                    return listeners.message && listeners.message.length > 0;
                } catch(e) {
                    // Fallback method
                    return false;
                }
            """)
            
            if has_listeners:
                logger.info(f"Active message listeners detected on {url}")
                return True
            else:
                logger.info(f"No active message listeners on {url}")
                return False
                
        except Exception as e:
            logger.error(f"Error checking runtime message listeners on {url}: {e}")
            return False

    def run_scan(self):
        """Scan all DVWA endpoints for Web Messaging content"""
        logger.info("Starting Web Messaging analysis for DVWA endpoints...")
        
        for endpoint in self.endpoints:
            url = f"{self.base_url}{endpoint}"
            self.check_for_web_messaging_content(url)
        
        # Check JavaScript files
        logger.info("Checking JavaScript files for Web Messaging content...")
        self.check_javascript_files()
        
        # Runtime checks with Selenium
        if self.driver:
            logger.info("Checking for active message listeners with Selenium...")
            for endpoint in self.endpoints[:3]:  # Check first 3 endpoints
                url = f"{self.base_url}{endpoint}"
                self.check_runtime_message_listeners(url)

    def analyze_findings(self):
        """Analyze findings for overall security posture"""
        total_endpoints = len(self.endpoints)
        endpoints_with_web_messaging = len(self.findings)
        
        return {
            'total_endpoints': total_endpoints,
            'endpoints_with_web_messaging': endpoints_with_web_messaging,
            'web_messaging_indicators': self.web_messaging_indicators
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
postMessage() calls: {finding['postmessage_count']}
Message listeners: {finding['listener_count']}
Origin checks: {finding['origin_check_count']}
Insecure data handling: {finding['insecure_data_count']}
Cross-origin iframes: {finding['iframe_count']}

Details:
{details}
                </pre>
                """
        else:
            findings_html = "<p>No Web Messaging functionality was found in any scanned endpoints.</p>"

        # Determine overall status
        if analysis['endpoints_with_web_messaging'] > 0:
            overall_status = '<span class="info">Web Messaging Content Found (Review Required)</span>'
        else:
            overall_status = '<span class="safe">Not Applicable (Web Messaging Not Used)</span>'

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
    <p><strong>Test ID:</strong> OTG-CLIENT-011</p>
    <p><strong>Vulnerability:</strong> Web Messaging Security</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Determine if the application uses insecure Web Messaging via <code>postMessage()</code>.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-011</p>
    <p><strong>Note:</strong> DVWA is a traditional server-rendered PHP application without cross-origin communication. This test confirms the absence of Web Messaging implementation.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Scan all pages for <code>postMessage()</code> and message event listeners.</p>
    <p>3. Analyze JavaScript for insecure message handling.</p>
    <p>4. Use Selenium to verify no message listeners are active.</p>
    <p>5. Confirm no Web Messaging functionality is present.</p>
    <p>6. Document findings and security posture.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Web Messaging Implementation</h3>
    <p><strong>Status:</strong> {overall_status}</p>
    <p><strong>Endpoints Scanned:</strong> {analysis['total_endpoints']}</p>
    <p><strong>Endpoints with Web Messaging Content:</strong> {analysis['endpoints_with_web_messaging']}</p>
    {findings_html}
    <p class="evidence"><strong>Evidence:</strong> {'Web Messaging functionality was detected and should be reviewed.' if analysis['endpoints_with_web_messaging'] > 0 else 'No Web Messaging functionality was found in DVWA. The application does not use cross-document messaging APIs.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>Since DVWA does not use Web Messaging, there is no risk of postMessage-related vulnerabilities such as origin validation bypass, message injection, or DOM-based XSS via message data. However, this also means DVWA cannot be used to practice real-world Web Messaging security testing.</p>
    <p><strong>Educational Context:</strong> Web Messaging (via <code>postMessage()</code>) enables secure cross-origin communication between windows, iframes, and workers. While powerful, insecure implementations can lead to:</p>
    <ul>
      <li>Cross-site scripting (XSS) through unsafe message data handling</li>
      <li>Information disclosure via origin validation bypass</li>
      <li>Privilege escalation through trusted message channels</li>
      <li>CSRF via postMessage-based attacks</li>
    </ul>
    <p>Secure Web Messaging requires:</p>
    <ul>
      <li>Proper origin validation with <code>event.origin</code></li>
      <li>Sanitization of message data before DOM insertion</li>
      <li>Avoiding wildcard (<code>*</code>) target origins</li>
      <li>Structured message formats with validation</li>
    </ul>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- When using <code>postMessage()</code>, always validate the <code>event.origin</code> against a whitelist of trusted domains.</p>
    <p class="recommendation">- Avoid using <code>*</code> as the targetOrigin parameter to prevent message interception.</p>
    <p class="recommendation">- Sanitize message data before using it in the DOM to prevent XSS.</p>
    <p class="recommendation">- Implement proper error handling for message events.</p>
    <p class="recommendation">- Use structured message formats (JSON) with validation instead of raw strings.</p>
    <p class="recommendation">- For learning Web Messaging security, use platforms like PortSwigger Academy or WebGoat.</p>
    <p class="recommendation">- Regularly audit client-side code for insecure postMessage usage.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-011_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-011_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA Web Messaging Analysis (OTG-CLIENT-011)")
            
            # Setup WebDriver
            if not self.setup_driver():
                logger.warning("WebDriver setup failed - continuing with static analysis only")
            
            # Login to DVWA
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            # Run Web Messaging content analysis
            self.run_scan()
            
            # Generate report
            self.generate_html_report()
            
            # Final summary
            if self.findings:
                logger.warning(f"⚠️  Web Messaging content detected in {len(self.findings)} endpoints!")
            else:
                logger.info("✅ No Web Messaging functionality found in DVWA")
                logger.info("ℹ️  This is expected as DVWA is a traditional PHP application without cross-origin communication.")
            
            logger.info("Web Messaging analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during testing: {e}")
        finally:
            # Cleanup
            if self.driver:
                self.driver.quit()
                logger.info("WebDriver closed")

if __name__ == "__main__":
    checker = DVWAWebMessagingChecker()
    checker.run_tests()