#!/usr/bin/env python3
"""
DVWA Circumvention of Work Flows (OTG-BUSLOGIC-006) Test Script
Author: AI Security Agent
Description: Automated testing for business logic workflow bypass vulnerabilities in DVWA
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

class DVWAWorkflowBypassTester:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.driver = None
        self.findings = {
            'direct_security_change': {'vulnerable': False, 'evidence': '', 'method': ''},
            'csrf_module_access': {'vulnerable': False, 'evidence': '', 'method': ''},
            'hidden_field_manipulation': {'vulnerable': False, 'evidence': '', 'method': ''}
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

    def test_direct_security_level_change(self):
        """Test if security level can be changed without UI interaction"""
        try:
            logger.info("Testing direct security level change...")
            
            # First, check current security level
            response = self.session.get(f"{self.base_url}/security.php")
            current_level = "unknown"
            if "Security level is currently: <em>low</em>" in response.text:
                current_level = "low"
            elif "Security level is currently: <em>medium</em>" in response.text:
                current_level = "medium"
            elif "Security level is currently: <em>high</em>" in response.text:
                current_level = "high"
            
            logger.info(f"Current security level: {current_level}")
            
            # Try to change security level directly via POST request
            # Get the user token first
            soup = BeautifulSoup(response.text, 'html.parser')
            user_token_input = soup.find('input', {'name': 'user_token'})
            user_token = ''
            if user_token_input and user_token_input.get('value'):
                user_token = user_token_input['value']
                logger.info(f"Extracted user token for security change: {user_token}")
            
            # Attempt to change to high security directly
            security_data = {
                'security': 'high',
                'seclev_submit': 'Submit'
            }
            
            if user_token:
                security_data['user_token'] = user_token
            
            # Send the request
            change_response = self.session.post(f"{self.base_url}/security.php", data=security_data)
            
            # Check if the change was successful
            if "Security level is currently: <em>high</em>" in change_response.text:
                self.findings['direct_security_change']['vulnerable'] = True
                self.findings['direct_security_change']['method'] = "Direct POST request to security.php"
                self.findings['direct_security_change']['evidence'] = f"Security level changed from {current_level} to high via direct request\nRequest: POST /security.php with security=high"
                logger.info("Direct security level change successful - Workflow bypass detected")
                
                # Change back to low for other tests
                security_data['security'] = 'low'
                self.session.post(f"{self.base_url}/security.php", data=security_data)
                logger.info("Security level changed back to low")
            else:
                self.findings['direct_security_change']['evidence'] = f"Attempted to change security level from {current_level} to high, but was denied"
                logger.info("Direct security level change was properly blocked")
                
        except Exception as e:
            logger.error(f"Error testing direct security level change: {e}")

    def test_csrf_module_direct_access(self):
        """Test if CSRF module can be accessed without proper workflow"""
        try:
            logger.info("Testing CSRF module direct access...")
            
            # Try to access CSRF module directly
            response = self.session.get(f"{self.base_url}/vulnerabilities/csrf/")
            
            # Check if we can access the page
            if response.status_code == 200 and "CSRF" in response.text:
                self.findings['csrf_module_access']['vulnerable'] = True
                self.findings['csrf_module_access']['method'] = "Direct URL access"
                self.findings['csrf_module_access']['evidence'] = f"CSRF module accessed directly without workflow validation\nURL: {self.base_url}/vulnerabilities/csrf/\nStatus Code: {response.status_code}"
                logger.info("CSRF module accessible via direct access - Workflow bypass detected")
            else:
                self.findings['csrf_module_access']['evidence'] = f"CSRF module access denied\nStatus Code: {response.status_code}"
                logger.info("CSRF module access properly restricted")
                
        except Exception as e:
            logger.error(f"Error testing CSRF module direct access: {e}")

    def test_hidden_field_manipulation(self):
        """Test manipulation of hidden form fields"""
        try:
            logger.info("Testing hidden field manipulation...")
            
            # Get the security page to examine form structure
            response = self.session.get(f"{self.base_url}/security.php")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Look for hidden security field
            security_inputs = soup.find_all('input', {'name': 'security'})
            hidden_fields = [inp for inp in security_inputs if inp.get('type') == 'hidden']
            
            if hidden_fields:
                self.findings['hidden_field_manipulation']['evidence'] = "Hidden security field found in form"
                logger.info("Hidden security field detected in form")
                
                # Try to manipulate by sending different values
                user_token_input = soup.find('input', {'name': 'user_token'})
                user_token = ''
                if user_token_input and user_token_input.get('value'):
                    user_token = user_token_input['value']
                
                # Test with medium security
                security_data = {
                    'security': 'medium',
                    'seclev_submit': 'Submit'
                }
                
                if user_token:
                    security_data['user_token'] = user_token
                
                change_response = self.session.post(f"{self.base_url}/security.php", data=security_data)
                
                if "Security level is currently: <em>medium</em>" in change_response.text:
                    self.findings['hidden_field_manipulation']['vulnerable'] = True
                    self.findings['hidden_field_manipulation']['method'] = "Hidden field manipulation"
                    self.findings['hidden_field_manipulation']['evidence'] += f"\nSuccessfully changed security level to medium via direct request"
                    logger.info("Hidden field manipulation successful")
                    
                    # Change back to low
                    security_data['security'] = 'low'
                    self.session.post(f"{self.base_url}/security.php", data=security_data)
                else:
                    self.findings['hidden_field_manipulation']['evidence'] += f"\nAttempt to manipulate hidden field was blocked"
                    logger.info("Hidden field manipulation was blocked")
            else:
                self.findings['hidden_field_manipulation']['evidence'] = "No hidden security fields found in forms"
                logger.info("No hidden security fields found")
                
        except Exception as e:
            logger.error(f"Error testing hidden field manipulation: {e}")

    def test_privilege_escalation_via_parameters(self):
        """Test privilege escalation by manipulating URL parameters"""
        try:
            logger.info("Testing privilege escalation via parameters...")
            
            # Try accessing admin functions with different parameters
            test_urls = [
                f"{self.base_url}/setup.php",  # Setup page
                f"{self.base_url}/instructions.php?security=high",  # Try to force high security via parameter
                f"{self.base_url}/index.php?admin=true",  # Try admin parameter
                f"{self.base_url}/security.php?level=highest"  # Try custom level parameter
            ]
            
            accessible_pages = []
            for url in test_urls:
                try:
                    response = self.session.get(url)
                    if response.status_code == 200:
                        accessible_pages.append(f"URL: {url} - Status: {response.status_code}")
                        logger.info(f"Accessible page: {url}")
                except:
                    continue
            
            if accessible_pages:
                self.findings['direct_security_change']['evidence'] += f"\nAdditional accessible pages via parameter manipulation:\n" + "\n".join(accessible_pages)
                logger.info("Found accessible pages via parameter manipulation")
            else:
                logger.info("No additional pages accessible via parameter manipulation")
                
        except Exception as e:
            logger.error(f"Error testing privilege escalation via parameters: {e}")

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # HTML escape findings for safe display in report
        direct_evidence = html.escape(self.findings['direct_security_change'].get('evidence', ''))
        csrf_evidence = html.escape(self.findings['csrf_module_access'].get('evidence', ''))
        hidden_evidence = html.escape(self.findings['hidden_field_manipulation'].get('evidence', ''))
        
        direct_method = html.escape(self.findings['direct_security_change'].get('method', ''))
        csrf_method = html.escape(self.findings['csrf_module_access'].get('method', ''))
        hidden_method = html.escape(self.findings['hidden_field_manipulation'].get('method', ''))
        
        # Properly escape HTML tags for display in the report template
        hidden_input_escaped = html.escape('<input type="hidden" name="security" value="low">')
        
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
    <p><strong>Test ID:</strong> OTG-BUSLOGIC-006</p>
    <p><strong>Vulnerability:</strong> Circumvention of Work Flows</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify if business workflows can be circumvented by skipping steps or manipulating state.</p>
    <p><strong>OWASP Reference:</strong> OTG-BUSLOGIC-006</p>
    <p><strong>Description:</strong> Workflow circumvention occurs when an application fails to enforce proper sequencing or state validation, allowing attackers to bypass intended processes.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Attempt to access high-security modules without changing security level via UI.</p>
    <p>3. Modify hidden form fields (e.g., <code>{hidden_input_escaped}</code>) in requests.</p>
    <p>4. Replay or reorder actions to test for improper state validation.</p>
    <p>5. Analyze server responses for access control enforcement.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Workflow Bypass via Direct Access</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['direct_security_change']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['direct_security_change']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Tested Action:</strong> Changing security level without UI interaction</p>
    <p><strong>Method:</strong> {direct_method or 'N/A'}</p>
    <pre>{direct_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'Security level changed without following UI workflow.' if self.findings['direct_security_change']['vulnerable'] else 'Workflow properly enforced.'}</p>

    <h3>CSRF Module Direct Access</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['csrf_module_access']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['csrf_module_access']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Tested Action:</strong> Accessing CSRF module without proper workflow</p>
    <p><strong>Method:</strong> {csrf_method or 'N/A'}</p>
    <pre>{csrf_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'CSRF module accessible via direct URL access.' if self.findings['csrf_module_access']['vulnerable'] else 'CSRF module access properly restricted.'}</p>

    <h3>Hidden Field Manipulation</h3>
    <p><strong>Status:</strong> <span class="{'vulnerable' if self.findings['hidden_field_manipulation']['vulnerable'] else 'safe'}">
        {'Vulnerable' if self.findings['hidden_field_manipulation']['vulnerable'] else 'Not Vulnerable'}
    </span></p>
    <p><strong>Tested Action:</strong> Manipulating hidden form fields for privilege escalation</p>
    <p><strong>Method:</strong> {hidden_method or 'N/A'}</p>
    <pre>{hidden_evidence or 'No evidence of vulnerability found'}</pre>
    <p class="evidence"><strong>Evidence:</strong> {'Hidden fields manipulated to change security level.' if self.findings['hidden_field_manipulation']['vulnerable'] else 'Hidden field manipulation properly blocked.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can bypass intended application workflows, escalate privileges, or perform unauthorized actions by manipulating requests or skipping validation steps. This undermines the application's business logic and access controls.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Enforce workflow state on the server side, not just client/UI.</p>
    <p class="recommendation">- Validate all steps in multi-stage processes before allowing progression.</p>
    <p class="recommendation">- Use server-side session flags to track workflow progress.</p>
    <p class="recommendation">- Implement proper access controls for all endpoints.</p>
    <p class="recommendation">- Log and monitor attempts to bypass workflow steps.</p>
    <p class="recommendation">- Validate and sanitize all form inputs, including hidden fields.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-BUSLOGIC-006_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-BUSLOGIC-006_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA Workflow Bypass Test (OTG-BUSLOGIC-006)")
            
            # Setup
            self.setup_driver()
            
            # Login and configure
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            # Run tests
            logger.info("Testing direct security level change...")
            self.test_direct_security_level_change()
            
            logger.info("Testing CSRF module direct access...")
            self.test_csrf_module_direct_access()
            
            logger.info("Testing hidden field manipulation...")
            self.test_hidden_field_manipulation()
            
            logger.info("Testing privilege escalation via parameters...")
            self.test_privilege_escalation_via_parameters()
            
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
    tester = DVWAWorkflowBypassTester()
    tester.run_tests()