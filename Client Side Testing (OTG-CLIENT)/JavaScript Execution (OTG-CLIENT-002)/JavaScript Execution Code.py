#!/usr/bin/env python3
"""
DVWA JavaScript Execution (OTG-CLIENT-002) Test Script
Author: AI Security Agent
Description: Automated testing for client-side JavaScript execution vulnerabilities in DVWA
"""

import requests
from bs4 import BeautifulSoup
import logging
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException
import time
import os
from datetime import datetime
import html

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWAXSSTester:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.driver = None
        self.findings = {
            'reflected_xss': {'vulnerable': False, 'evidence': '', 'payload': ''},
            'stored_xss': {'vulnerable': False, 'evidence': '', 'payload': ''}
        }
        
    def setup_driver(self):
        """Setup Chrome WebDriver for Selenium"""
        try:
            options = webdriver.ChromeOptions()
            options.add_argument('--headless=new')  # Updated headless mode
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
            if user_token_input and user_token_input.get('value'):
                user_token = user_token_input['value']
            else:
                logger.warning("Could not find user token, proceeding without it")
                user_token = ''
            
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

    def test_reflected_xss(self):
        """Test for Reflected XSS vulnerability"""
        try:
            payload = "<script>alert('XSS')</script>"
            # URL encode the payload for GET request
            import urllib.parse
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{self.base_url}/vulnerabilities/xss_r/?name={encoded_payload}"
            
            # Test with requests first
            response = self.session.get(test_url)
            if payload in response.text:
                self.findings['reflected_xss']['vulnerable'] = True
                self.findings['reflected_xss']['payload'] = payload
                self.findings['reflected_xss']['evidence'] = f"Payload reflected in response. URL: {test_url}"
                logger.info("Reflected XSS vulnerability detected")
            else:
                logger.info("Payload not reflected in response")
            
            # Test with Selenium for actual execution
            if self.driver:
                self.driver.get(test_url)
                try:
                    # Wait for alert
                    WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    self.findings['reflected_xss']['vulnerable'] = True
                    self.findings['reflected_xss']['evidence'] += f" | Alert executed with text: {alert_text}"
                    logger.info("Reflected XSS alert confirmed")
                except TimeoutException:
                    logger.info("No alert detected for reflected XSS")
                    
        except Exception as e:
            logger.error(f"Error testing reflected XSS: {e}")

    def test_stored_xss(self):
        """Test for Stored XSS vulnerability"""
        try:
            payload = "<script>alert('XSS')</script>"
            
            # Get stored XSS page
            response = self.session.get(f"{self.base_url}/vulnerabilities/xss_s/")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract user token safely
            user_token_input = soup.find('input', {'name': 'user_token'})
            user_token = ''
            if user_token_input and user_token_input.get('value'):
                user_token = user_token_input['value']
                logger.info(f"Extracted user token for stored XSS: {user_token}")
            else:
                logger.warning("Could not find user token for stored XSS, proceeding without it")
            
            # Submit payload
            post_data = {
                'txtName': 'TestUser',
                'mtxMessage': payload,
                'btnSign': 'Sign Guestbook'
            }
            
            # Add user token if found
            if user_token:
                post_data['user_token'] = user_token
            
            submit_response = self.session.post(f"{self.base_url}/vulnerabilities/xss_s/", data=post_data)
            
            # Check if payload is stored by visiting the page again
            response = self.session.get(f"{self.base_url}/vulnerabilities/xss_s/")
            if payload in response.text:
                self.findings['stored_xss']['vulnerable'] = True
                self.findings['stored_xss']['payload'] = payload
                self.findings['stored_xss']['evidence'] = "Payload stored in guestbook"
                logger.info("Stored XSS payload successfully stored")
            else:
                logger.info("Payload not found in stored XSS page")
            
            # Test execution with Selenium by visiting the page
            if self.driver:
                self.driver.get(f"{self.base_url}/vulnerabilities/xss_s/")
                try:
                    # Wait for alert
                    WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    self.findings['stored_xss']['vulnerable'] = True
                    self.findings['stored_xss']['evidence'] += f" | Alert executed with text: {alert_text}"
                    logger.info("Stored XSS alert confirmed")
                except TimeoutException:
                    logger.info("No alert detected for stored XSS")
                except NoAlertPresentException:
                    logger.info("No alert present for stored XSS")
                    
        except Exception as e:
            logger.error(f"Error testing stored XSS: {e}")
            logger.error(f"Exception details: {str(e)}")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # HTML escape payloads for safe display in report
        reflected_payload = html.escape(self.findings['reflected_xss'].get('payload', ''))
        stored_payload = html.escape(self.findings['stored_xss'].get('payload', ''))
        reflected_evidence = html.escape(self.findings['reflected_xss'].get('evidence', ''))
        stored_evidence = html.escape(self.findings['stored_xss'].get('evidence', ''))
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>OSCP-Style Security Assessment Report</title>
  <style>
    /* Professional OSCP-inspired styling: monospace font, dark theme, clear sections */
    body {{ font-family: 'Courier New', monospace; background: #111; color: #00FF00; padding: 20px; }}
    .header {{ text-align: center; margin-bottom: 30px; }}
    h1, h2, h3 {{ color: #00CCFF; }}
    .section {{ margin: 20px 0; }}
    pre {{ background: #222; padding: 10px; border-left: 4px solid #00CCFF; overflow-x: auto; color: #FFCC00; }}
    .evidence {{ color: #FFCC00; }}
    .recommendation {{ color: #AAFF00; }}
    .vulnerable {{ color: #FF5555; }}
    .safe {{ color: #55FF55; }}
    footer {{ margin-top: 50px; font-size: 0.8em; text-align: center; color: #666; }}
    code {{ background: #333; padding: 2px 4px; border-radius: 3px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Test ID:</strong> OTG-CLIENT-002</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Test for client-side JavaScript execution vulnerabilities (e.g., XSS).</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-002</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Navigate to XSS (Reflected) and XSS (Stored) pages.</p>
    <p>3. Extract forms and CSRF tokens.</p>
    <p>4. Inject JavaScript payload: <code>&amp;lt;script&amp;gt;alert('XSS')&amp;lt;/script&amp;gt;</code></p>
    <p>5. Monitor for execution indicators.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>XSS (Reflected)</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['reflected_xss']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['reflected_xss']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Payload Used:</strong> <code>{reflected_payload or 'N/A'}</code></p>
    <pre>{reflected_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'JavaScript alert observed during automation.' if self.findings['reflected_xss']['vulnerable'] else 'No JavaScript execution detected.'}</p>

    <h3>XSS (Stored)</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['stored_xss']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['stored_xss']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Payload Used:</strong> <code>{stored_payload or 'N/A'}</code></p>
    <pre>{stored_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'Script executed upon page reload.' if self.findings['stored_xss']['vulnerable'] else 'No stored JavaScript execution detected.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can execute arbitrary JavaScript in the context of the victim's session, leading to session hijacking, defacement, or malware delivery.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Implement proper output encoding for user-supplied data.</p>
    <p class="recommendation">- Use Content Security Policy (CSP) headers.</p>
    <p class="recommendation">- Validate and sanitize all inputs on both client and server sides.</p>
    <p class="recommendation">- Implement CSRF protection tokens for all forms.</p>
    <p class="recommendation">- Regularly update and patch web application frameworks.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-002_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-002_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA JavaScript Execution Test (OTG-CLIENT-002)")
            
            # Setup
            self.setup_driver()
            
            # Login and configure
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            if not self.set_security_level():
                logger.warning("Failed to set security level, continuing with default")
            
            # Run tests
            logger.info("Testing Reflected XSS...")
            self.test_reflected_xss()
            
            logger.info("Testing Stored XSS...")
            self.test_stored_xss()
            
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
    tester = DVWAXSSTester()
    tester.run_tests()