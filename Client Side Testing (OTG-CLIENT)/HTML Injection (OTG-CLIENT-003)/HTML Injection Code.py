#!/usr/bin/env python3
"""
DVWA HTML Injection (OTG-CLIENT-003) Test Script
Author: AI Security Agent
Description: Automated testing for HTML injection vulnerabilities in DVWA
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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWAHTMLInjectionTester:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.driver = None
        self.findings = {
            'reflected_html': {'vulnerable': False, 'evidence': '', 'payload': ''},
            'stored_html': {'vulnerable': False, 'evidence': '', 'payload': ''}
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

    def test_reflected_html_injection(self):
        """Test for Reflected HTML Injection vulnerability"""
        try:
            # Use a visible HTML payload that doesn't execute scripts
            payload = '<h1 style="color:red;">INJECTED HTML</h1>'
            
            # URL encode the payload for GET request
            import urllib.parse
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{self.base_url}/vulnerabilities/xss_r/?name={encoded_payload}"
            
            # Test with requests first
            response = self.session.get(test_url)
            if payload in response.text:
                self.findings['reflected_html']['vulnerable'] = True
                self.findings['reflected_html']['payload'] = payload
                self.findings['reflected_html']['evidence'] = f"HTML payload reflected in response. URL: {test_url}"
                logger.info("Reflected HTML Injection vulnerability detected")
            else:
                logger.info("HTML payload not reflected in response")
            
            # Test with Selenium for actual rendering verification
            if self.driver:
                self.driver.get(test_url)
                page_source = self.driver.page_source
                
                # Check if the injected HTML is present in the DOM
                if payload in page_source:
                    self.findings['reflected_html']['vulnerable'] = True
                    self.findings['reflected_html']['evidence'] += " | HTML payload rendered in page DOM"
                    logger.info("Reflected HTML Injection confirmed in DOM")
                    
                    # Additional check for specific element presence
                    try:
                        heading_element = self.driver.find_element(By.XPATH, "//h1[@style='color:red;']")
                        if heading_element:
                            self.findings['reflected_html']['evidence'] += " | Injected <h1> element found in DOM"
                            logger.info("Injected heading element confirmed")
                    except:
                        logger.info("Could not locate specific injected element")
                
        except Exception as e:
            logger.error(f"Error testing reflected HTML injection: {e}")

    def test_stored_html_injection(self):
        """Test for Stored HTML Injection vulnerability"""
        try:
            # Use a visible HTML payload that doesn't execute scripts
            payload = '<b>Bold Text via Injection</b>'
            
            # Get stored XSS page
            response = self.session.get(f"{self.base_url}/vulnerabilities/xss_s/")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract user token safely
            user_token_input = soup.find('input', {'name': 'user_token'})
            user_token = ''
            if user_token_input and user_token_input.get('value'):
                user_token = user_token_input['value']
                logger.info(f"Extracted user token for stored HTML injection: {user_token}")
            else:
                logger.warning("Could not find user token for stored HTML injection, proceeding without it")
            
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
                self.findings['stored_html']['vulnerable'] = True
                self.findings['stored_html']['payload'] = payload
                self.findings['stored_html']['evidence'] = "HTML payload stored in guestbook"
                logger.info("Stored HTML Injection payload successfully stored")
            else:
                logger.info("HTML payload not found in stored HTML injection page")
            
            # Test rendering with Selenium by visiting the page
            if self.driver:
                self.driver.get(f"{self.base_url}/vulnerabilities/xss_s/")
                page_source = self.driver.page_source
                
                # Check if the injected HTML is present in the DOM
                if payload in page_source:
                    self.findings['stored_html']['vulnerable'] = True
                    self.findings['stored_html']['evidence'] += " | HTML payload rendered in page DOM on reload"
                    logger.info("Stored HTML Injection confirmed in DOM")
                    
                    # Additional check for specific element presence
                    try:
                        bold_element = self.driver.find_element(By.XPATH, "//b[text()='Bold Text via Injection']")
                        if bold_element:
                            self.findings['stored_html']['evidence'] += " | Injected <b> element found in DOM"
                            logger.info("Injected bold element confirmed")
                    except:
                        logger.info("Could not locate specific injected element")
                
        except Exception as e:
            logger.error(f"Error testing stored HTML injection: {e}")
            logger.error(f"Exception details: {str(e)}")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # HTML escape payloads for safe display in report
        reflected_payload = html.escape(self.findings['reflected_html'].get('payload', ''))
        stored_payload = html.escape(self.findings['stored_html'].get('payload', ''))
        reflected_evidence = html.escape(self.findings['reflected_html'].get('evidence', ''))
        stored_evidence = html.escape(self.findings['stored_html'].get('evidence', ''))
        
        # Properly escape HTML tags for display in the report template
        h1_escaped = html.escape('<h1>')
        b_escaped = html.escape('<b>')
        img_escaped = html.escape('<img>')
        
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
    <p><strong>Test ID:</strong> OTG-CLIENT-003</p>
    <p><strong>Vulnerability:</strong> HTML Injection</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify HTML injection vulnerabilities in user input fields.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-003</p>
    <p><strong>Description:</strong> HTML Injection occurs when user input is embedded in the page output without proper sanitization, allowing attackers to inject visible HTML content.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Navigate to vulnerable input forms (e.g., XSS Reflected/Stores).</p>
    <p>4. Inject HTML payloads such as <code>{h1_escaped}</code>, <code>{b_escaped}</code>, <code>{img_escaped}</code>.</p>
    <p>5. Capture server responses and DOM state.</p>
    <p>6. Verify rendering via browser automation.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Reflected HTML Injection</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['reflected_html']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['reflected_html']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Payload Used:</strong> <code>{reflected_payload or 'N/A'}</code></p>
    <pre>{reflected_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'HTML payload rendered in response.' if self.findings['reflected_html']['vulnerable'] else 'No HTML injection detected.'}</p>

    <h3>Stored HTML Injection</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['stored_html']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['stored_html']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Payload Used:</strong> <code>{stored_payload or 'N/A'}</code></p>
    <pre>{stored_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'HTML payload stored and rendered on page reload.' if self.findings['stored_html']['vulnerable'] else 'No stored HTML injection detected.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can alter the visual appearance of the web page, potentially misleading users, injecting fake forms, or redirecting clicks. While less severe than XSS, it can be used for phishing and UI redressing.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Sanitize all user inputs using libraries like DOMPurify or OWASP Java Encoder.</p>
    <p class="recommendation">- Implement proper output encoding based on context (HTML, HTML attribute, JS, CSS, URL).</p>
    <p class="recommendation">- Use Content Security Policy (CSP) to restrict inline scripts and unauthorized resources.</p>
    <p class="recommendation">- Validate input length, format, and allowed HTML tags if rich text is required.</p>
    <p class="recommendation">- Implement CSRF protection tokens for all forms.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-003_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-003_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA HTML Injection Test (OTG-CLIENT-003)")
            
            # Setup
            self.setup_driver()
            
            # Login and configure
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            if not self.set_security_level():
                logger.warning("Failed to set security level, continuing with default")
            
            # Run tests
            logger.info("Testing Reflected HTML Injection...")
            self.test_reflected_html_injection()
            
            logger.info("Testing Stored HTML Injection...")
            self.test_stored_html_injection()
            
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
    tester = DVWAHTMLInjectionTester()
    tester.run_tests()