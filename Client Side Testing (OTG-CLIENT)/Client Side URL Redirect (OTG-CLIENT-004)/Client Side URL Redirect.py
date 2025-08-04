#!/usr/bin/env python3
"""
DVWA Client-Side URL Redirect (OTG-CLIENT-004) Test Script
Author: AI Security Agent
Description: Automated testing for client-side URL redirect vulnerabilities in DVWA
"""

import requests
from bs4 import BeautifulSoup
import logging
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time
import os
from datetime import datetime
import html
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWAClientSideRedirectTester:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.driver = None
        self.findings = {
            'client_redirect': {'vulnerable': False, 'evidence': '', 'parameter': '', 'payload': ''}
        }
        
    def setup_driver(self):
        """Setup Chrome WebDriver for Selenium"""
        try:
            options = webdriver.ChromeOptions()
            options.add_argument('--headless=new')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-plugins')
            options.add_argument('--disable-images')
            options.add_argument('--disable-javascript=false')
            options.add_experimental_option('useAutomationExtension', False)
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            
            self.driver = webdriver.Chrome(options=options)
            self.driver.implicitly_wait(10)
            logger.info("WebDriver initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize WebDriver: {e}")
            raise

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

    def set_security_level(self):
        """Set DVWA security level to Low"""
        try:
            response = self.session.get(f"{self.base_url}/security.php")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract user token
            user_token_input = soup.find('input', {'name': 'user_token'})
            user_token = ''
            if user_token_input and user_token_input.get('value'):
                user_token = user_token_input['value']
            else:
                logger.warning("Could not find user token, proceeding without it")
            
            # Set security to low
            security_data = {
                'security': 'low',
                'seclev_submit': 'Submit'
            }
            
            # Add user token if found
            if user_token:
                security_data['user_token'] = user_token
            
            self.session.post(f"{self.base_url}/security.php", data=security_data)
            logger.info("Security level set to Low")
            return True
            
        except Exception as e:
            logger.error(f"Error setting security level: {e}")
            return False

    def find_redirect_vulnerabilities(self):
        """Scan for potential redirect vulnerabilities in DVWA"""
        try:
            # Check if DVWA has a redirect module
            redirect_pages = [
                "/vulnerabilities/redirect/",
                "/redirect.php",
                "/redirect"
            ]
            
            found_redirect_page = None
            for page in redirect_pages:
                try:
                    response = self.session.get(f"{self.base_url}{page}")
                    if response.status_code == 200:
                        found_redirect_page = page
                        logger.info(f"Found potential redirect page: {page}")
                        break
                except:
                    continue
            
            if not found_redirect_page:
                # If no dedicated redirect page, check other pages for redirect parameters
                logger.info("No dedicated redirect page found, checking for redirect parameters in other pages")
                return self.check_for_redirect_parameters()
            else:
                return self.test_redirect_page(found_redirect_page)
                
        except Exception as e:
            logger.error(f"Error scanning for redirect vulnerabilities: {e}")
            return False

    def check_for_redirect_parameters(self):
        """Check various DVWA pages for redirect parameters"""
        try:
            # Check common DVWA pages for redirect functionality
            pages_to_check = [
                "/",
                "/index.php",
                "/vulnerabilities/exec/",
                "/vulnerabilities/sqli/",
                "/vulnerabilities/xss_r/",
                "/vulnerabilities/xss_s/"
            ]
            
            redirect_indicators = ['redirect=', 'url=', 'next=', 'to=', 'goto=']
            
            for page in pages_to_check:
                try:
                    response = self.session.get(f"{self.base_url}{page}")
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Check for redirect parameters in forms
                    forms = soup.find_all('form')
                    for form in forms:
                        action = form.get('action', '')
                        for indicator in redirect_indicators:
                            if indicator in action.lower():
                                logger.info(f"Found redirect parameter in form action: {action}")
                                return self.test_redirect_functionality(page, indicator.rstrip('='), action)
                    
                    # Check for redirect parameters in links
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link['href']
                        for indicator in redirect_indicators:
                            if indicator in href.lower():
                                logger.info(f"Found redirect parameter in link: {href}")
                                return self.test_redirect_functionality(page, indicator.rstrip('='), href)
                                
                    # Check for JavaScript redirect functionality
                    scripts = soup.find_all('script')
                    for script in scripts:
                        if script.string:
                            for indicator in redirect_indicators:
                                if indicator in script.string.lower():
                                    logger.info(f"Found redirect parameter in JavaScript: {indicator}")
                                    return self.test_js_redirect_functionality(page, indicator.rstrip('='))
                                    
                except Exception as e:
                    logger.warning(f"Error checking page {page}: {e}")
                    continue
                    
            logger.info("No redirect parameters found in common DVWA pages")
            return False
            
        except Exception as e:
            logger.error(f"Error checking for redirect parameters: {e}")
            return False

    def test_redirect_page(self, redirect_page):
        """Test a dedicated redirect page"""
        try:
            # Check the redirect page for parameters
            response = self.session.get(f"{self.base_url}{redirect_page}")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for common redirect parameter names
            redirect_params = ['url', 'redirect', 'next', 'to', 'goto']
            
            # Check form parameters
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                for input_field in inputs:
                    name = input_field.get('name', '').lower()
                    if name in redirect_params:
                        logger.info(f"Found redirect parameter in form: {name}")
                        return self.test_redirect_parameter(redirect_page, name)
            
            # Check URL parameters
            current_url = response.url
            parsed_url = urllib.parse.urlparse(current_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param in query_params:
                if param.lower() in redirect_params:
                    logger.info(f"Found redirect parameter in URL: {param}")
                    return self.test_redirect_parameter(redirect_page, param)
            
            # If no parameters found, try common ones
            logger.info("Testing common redirect parameters")
            for param in redirect_params:
                test_result = self.test_redirect_parameter(redirect_page, param)
                if test_result:
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error testing redirect page: {e}")
            return False

    def test_redirect_parameter(self, page, parameter):
        """Test a specific redirect parameter"""
        try:
            # Test with a safe external domain
            test_payload = "https://example.com"
            
            # Test via GET parameter
            test_url = f"{self.base_url}{page}?{parameter}={urllib.parse.quote(test_payload)}"
            
            logger.info(f"Testing redirect with URL: {test_url}")
            
            if self.driver:
                # Get the initial page
                self.driver.get(test_url)
                
                # Wait and capture the final URL
                time.sleep(3)
                final_url = self.driver.current_url
                
                logger.info(f"Final URL after redirect attempt: {final_url}")
                
                # Check if we were redirected to the test domain
                if "example.com" in final_url:
                    self.findings['client_redirect']['vulnerable'] = True
                    self.findings['client_redirect']['parameter'] = parameter
                    self.findings['client_redirect']['payload'] = test_payload
                    self.findings['client_redirect']['evidence'] = f"Redirect URL: {test_url}\nFinal Destination: {final_url}"
                    logger.info("Client-side redirect vulnerability confirmed")
                    return True
                else:
                    logger.info("No redirect to external domain detected")
                    
            return False
            
        except Exception as e:
            logger.error(f"Error testing redirect parameter: {e}")
            return False

    def test_js_redirect_functionality(self, page, parameter):
        """Test JavaScript-based redirect functionality"""
        try:
            test_payload = "https://example.com"
            
            # Test by injecting JavaScript redirect
            js_payload = f"javascript:window.location='{test_payload}'"
            test_url = f"{self.base_url}{page}?{parameter}={urllib.parse.quote(js_payload)}"
            
            logger.info(f"Testing JavaScript redirect with URL: {test_url}")
            
            if self.driver:
                initial_url = self.driver.current_url
                self.driver.get(test_url)
                
                # Wait for potential redirect
                time.sleep(3)
                final_url = self.driver.current_url
                
                # Check if we were redirected
                if "example.com" in final_url:
                    self.findings['client_redirect']['vulnerable'] = True
                    self.findings['client_redirect']['parameter'] = parameter
                    self.findings['client_redirect']['payload'] = js_payload
                    self.findings['client_redirect']['evidence'] = f"JS Redirect URL: {test_url}\nFinal Destination: {final_url}"
                    logger.info("JavaScript-based redirect vulnerability confirmed")
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error testing JavaScript redirect: {e}")
            return False

    def test_protocol_relative_redirect(self, page, parameter):
        """Test protocol-relative redirect"""
        try:
            test_payload = "//example.com"
            test_url = f"{self.base_url}{page}?{parameter}={urllib.parse.quote(test_payload)}"
            
            logger.info(f"Testing protocol-relative redirect with URL: {test_url}")
            
            if self.driver:
                self.driver.get(test_url)
                time.sleep(3)
                final_url = self.driver.current_url
                
                if "example.com" in final_url:
                    self.findings['client_redirect']['vulnerable'] = True
                    self.findings['client_redirect']['parameter'] = parameter
                    self.findings['client_redirect']['payload'] = test_payload
                    self.findings['client_redirect']['evidence'] = f"Protocol-relative Redirect URL: {test_url}\nFinal Destination: {final_url}"
                    logger.info("Protocol-relative redirect vulnerability confirmed")
                    return True
                    
            return False
            
        except Exception as e:
            logger.error(f"Error testing protocol-relative redirect: {e}")
            return False

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # HTML escape findings for safe display in report
        parameter = html.escape(self.findings['client_redirect'].get('parameter', ''))
        payload = html.escape(self.findings['client_redirect'].get('payload', ''))
        evidence = html.escape(self.findings['client_redirect'].get('evidence', ''))
        
        # Properly escape HTML tags for display in the report template
        redirect_escaped = html.escape('redirect=')
        url_escaped = html.escape('url=')
        next_escaped = html.escape('next=')
        
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
    footer {{ margin-top: 60px; font-size: 0.8em; text-align: center; color: #666; }}
    code {{ background: #333; padding: 2px 4px; border-radius: 3px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Test ID:</strong> OTG-CLIENT-004</p>
    <p><strong>Vulnerability:</strong> Client-Side URL Redirect</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify client-side URL redirect vulnerabilities that allow arbitrary redirection.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-004</p>
    <p><strong>Description:</strong> Client-side open redirects occur when JavaScript or HTML uses unvalidated user input to redirect users to external domains, potentially enabling phishing attacks.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Scan for redirect parameters in URLs and JavaScript code.</p>
    <p>4. Inject redirect payloads such as <code>{redirect_escaped}</code>, <code>{url_escaped}</code>, <code>{next_escaped}</code>.</p>
    <p>5. Monitor browser navigation and capture redirect behavior.</p>
    <p>6. Verify if external domains are reachable via redirect.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Client-Side Open Redirect</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['client_redirect']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['client_redirect']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Parameter Tested:</strong> <code>{parameter or 'N/A'}</code></p>
    <p><strong>Payload Used:</strong> <code>{payload or 'N/A'}</code></p>
    <pre>{evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'Browser successfully redirected to external domain.' if self.findings['client_redirect']['vulnerable'] else 'No client-side redirect vulnerability detected.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can craft malicious links that appear to come from a trusted domain but redirect users to phishing sites, malware distribution points, or scam pages. This can lead to credential theft and loss of trust in the legitimate application.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Avoid using user-controllable data in redirect locations.</p>
    <p class="recommendation">- Use a whitelist of allowed domains for redirection.</p>
    <p class="recommendation">- Implement server-side validation of redirect targets.</p>
    <p class="recommendation">- Replace direct URL redirects with ID-based mapping (e.g., redirect=1 → homepage).</p>
    <p class="recommendation">- Add user confirmation before external redirects.</p>
    <p class="recommendation">- Sanitize and validate all redirect parameters.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-004_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-004_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA Client-Side URL Redirect Test (OTG-CLIENT-004)")
            
            # Setup
            self.setup_driver()
            
            # Login and configure
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            if not self.set_security_level():
                logger.warning("Failed to set security level, continuing with default")
            
            # Run tests
            logger.info("Scanning for client-side redirect vulnerabilities...")
            self.find_redirect_vulnerabilities()
            
            # Generate report
            self.generate_html_report()
            
            logger.info("All tests completed successfully")
            
        except Exception as e:
            logger.error(f"Error during testing: {e}")
        finally:
            # Cleanup
            if self.driver:
                self.driver.quit()
                logger.info("WebDriver closed")

if __name__ == "__main__":
    tester = DVWAClientSideRedirectTester()
    tester.run_tests()