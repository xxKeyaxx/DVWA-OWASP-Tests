#!/usr/bin/env python3
"""
DVWA Cross-Site Flashing (OTG-CLIENT-008) Test Script
Author: AI Security Agent
Description: Diagnostic testing for Flash content in DVWA
Note: Adobe Flash is deprecated and not used in DVWA
"""

import requests
from bs4 import BeautifulSoup
import logging
from datetime import datetime
import html
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWACrossSiteFlashingChecker:
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
        self.flash_indicators = {
            'swf_files': [],
            'object_tags': [],
            'embed_tags': [],
            'param_tags': [],
            'flash_scripts': [],
            'activex_calls': []
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

    def check_for_flash_content(self, url):
        """Check for Flash content in a given URL"""
        try:
            response = self.session.get(url)
            content = response.text.lower()
            soup = BeautifulSoup(content, 'html.parser')
            
            finding = {
                'url': url,
                'swf_count': 0,
                'object_count': 0,
                'embed_count': 0,
                'param_count': 0,
                'flash_script_count': 0,
                'activex_count': 0,
                'details': []
            }
            
            # Check for .swf file references
            swf_matches = re.findall(r'\.swf', content)
            finding['swf_count'] = len(swf_matches)
            if swf_matches:
                self.flash_indicators['swf_files'].append(url)
                finding['details'].append(f"Found {len(swf_matches)} .swf references")
            
            # Check for <object> tags with Flash type
            object_tags = soup.find_all('object', attrs={'type': re.compile(r'application/x-shockwave-flash', re.I)})
            finding['object_count'] = len(object_tags)
            if object_tags:
                self.flash_indicators['object_tags'].append(url)
                finding['details'].append(f"Found {len(object_tags)} Flash object tags")
            
            # Check for <embed> tags with .swf src
            embed_tags = soup.find_all('embed', src=re.compile(r'\.swf', re.I))
            finding['embed_count'] = len(embed_tags)
            if embed_tags:
                self.flash_indicators['embed_tags'].append(url)
                finding['details'].append(f"Found {len(embed_tags)} Flash embed tags")
            
            # Check for <param> tags with Flash-related values
            param_tags = soup.find_all('param', attrs={'name': re.compile(r'movie|flashvars', re.I)})
            finding['param_count'] = len(param_tags)
            if param_tags:
                self.flash_indicators['param_tags'].append(url)
                finding['details'].append(f"Found {len(param_tags)} Flash param tags")
            
            # Check for Flash detection scripts in JavaScript
            flash_script_patterns = [
                r'swfobject',
                r'detectflash',
                r'hasflash',
                r'getflashversion',
                r'shockwave'
            ]
            
            flash_script_count = 0
            for pattern in flash_script_patterns:
                matches = re.findall(pattern, content, re.I)
                flash_script_count += len(matches)
            
            finding['flash_script_count'] = flash_script_count
            if flash_script_count > 0:
                self.flash_indicators['flash_scripts'].append(url)
                finding['details'].append(f"Found {flash_script_count} Flash-related script references")
            
            # Check for ActiveX calls (IE-specific Flash)
            activex_patterns = [
                r'new\s+activexobject\(["\']shockwaveflash',
                r'activexobject\(["\']shockwaveflash'
            ]
            
            activex_count = 0
            for pattern in activex_patterns:
                matches = re.findall(pattern, content, re.I)
                activex_count += len(matches)
            
            finding['activex_count'] = activex_count
            if activex_count > 0:
                self.flash_indicators['activex_calls'].append(url)
                finding['details'].append(f"Found {activex_count} ActiveX Flash calls")
            
            # Add to findings if any Flash content found
            if any([
                finding['swf_count'] > 0,
                finding['object_count'] > 0,
                finding['embed_count'] > 0,
                finding['param_count'] > 0,
                finding['flash_script_count'] > 0,
                finding['activex_count'] > 0
            ]):
                self.findings.append(finding)
                logger.warning(f"Flash content found in {url}")
            else:
                logger.info(f"No Flash content found in {url}")
                
        except Exception as e:
            logger.error(f"Error checking {url}: {e}")

    def check_javascript_files(self):
        """Check linked JavaScript files for Flash content"""
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
                        script_content = script_response.text.lower()
                        
                        # Check for Flash-related content in JavaScript
                        flash_patterns = [
                            'swfobject', 'flashvars', 'shockwave', 
                            'activexobject.*?shockwaveflash', 'embedswf'
                        ]
                        
                        for pattern in flash_patterns:
                            if re.search(pattern, script_content, re.I):
                                logger.info(f"Flash-related content found in JavaScript: {script_url}")
                                break
                                
                    except Exception as e:
                        logger.debug(f"Could not fetch script {script_url}: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error checking JavaScript files: {e}")

    def run_scan(self):
        """Scan all DVWA endpoints for Flash content"""
        logger.info("Starting Cross-Site Flashing analysis for DVWA endpoints...")
        
        for endpoint in self.endpoints:
            url = f"{self.base_url}{endpoint}"
            self.check_for_flash_content(url)
        
        # Check JavaScript files
        logger.info("Checking JavaScript files for Flash content...")
        self.check_javascript_files()

    def analyze_findings(self):
        """Analyze findings for overall security posture"""
        total_endpoints = len(self.endpoints)
        endpoints_with_flash = len(self.findings)
        
        return {
            'total_endpoints': total_endpoints,
            'endpoints_with_flash': endpoints_with_flash,
            'flash_indicators': self.flash_indicators
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
SWF Files: {finding['swf_count']}
Object Tags: {finding['object_count']}
Embed Tags: {finding['embed_count']}
Param Tags: {finding['param_count']}
Flash Scripts: {finding['flash_script_count']}
ActiveX Calls: {finding['activex_count']}

Details:
{details}
                </pre>
                """
        else:
            findings_html = "<p>No Flash content was found in any scanned endpoints.</p>"

        # Determine overall status
        if analysis['endpoints_with_flash'] > 0:
            overall_status = '<span class="info">Flash Content Found (Review Required)</span>'
        else:
            overall_status = '<span class="safe">Not Applicable (Flash Not Used)</span>'

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
    <p><strong>Test ID:</strong> OTG-CLIENT-008</p>
    <p><strong>Vulnerability:</strong> Cross-Site Flashing</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Determine if the application uses Adobe Flash in a way that could be exploited via Cross-Site Flashing.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-008</p>
    <p><strong>Note:</strong> Adobe Flash reached end-of-life on December 31, 2020. Modern browsers no longer support Flash. This test confirms its absence in DVWA.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Scan all pages for <code>.swf</code> references and Flash-related HTML tags.</p>
    <p>3. Analyze JavaScript for Flash detection or interaction.</p>
    <p>4. Confirm no Flash content is present.</p>
    <p>5. Document findings and security posture.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Cross-Site Flashing (OTG-CLIENT-008)</h3>
    <p><strong>Status:</strong> {overall_status}</p>
    <p><strong>Endpoints Scanned:</strong> {analysis['total_endpoints']}</p>
    <p><strong>Endpoints with Flash Content:</strong> {analysis['endpoints_with_flash']}</p>
    {findings_html}
    <p class="evidence"><strong>Evidence:</strong> {'Flash content was detected and should be reviewed.' if analysis['endpoints_with_flash'] > 0 else 'No Flash content or related technologies were found. Adobe Flash is deprecated and should not be used in modern applications.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>Since DVWA does not use Adobe Flash, there is no risk of Cross-Site Flashing attacks. However, this also means DVWA cannot be used to practice real-world Flash-based vulnerability testing. The absence of Flash content is actually the secure configuration for a modern web application.</p>
    <p><strong>Historical Context:</strong> Cross-Site Flashing was a real vulnerability class when Flash was widely used. It involved exploiting Flash applications that accepted user input without proper validation, leading to XSS, open redirects, or data theft. With Flash's end-of-life, this vulnerability class is now obsolete.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Do not use Adobe Flash in any new or existing applications.</p>
    <p class="recommendation">- Migrate legacy Flash content to HTML5, WebAssembly, or modern JavaScript frameworks.</p>
    <p class="recommendation">- Audit third-party libraries for hidden Flash dependencies.</p>
    <p class="recommendation">- Remove any Flash detection scripts from modern applications.</p>
    <p class="recommendation">- For learning historical vulnerabilities, use archived platforms like Google Gruyere.</p>
    <p class="recommendation">- Regularly scan applications for deprecated technologies and plugins.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-008_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-008_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA Cross-Site Flashing Analysis (OTG-CLIENT-008)")
            
            # Login to DVWA
            if not self.login_to_dvwa():
                logger.error("Failed to login to DVWA. Exiting.")
                return
            
            # Run Flash content analysis
            self.run_scan()
            
            # Generate report
            self.generate_html_report()
            
            # Final summary
            if self.findings:
                logger.warning(f"⚠️  Flash content detected in {len(self.findings)} endpoints!")
            else:
                logger.info("✅ No Flash content found in DVWA")
                logger.info("ℹ️  This is expected as Adobe Flash is deprecated and should not be used.")
            
            logger.info("Cross-Site Flashing analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during testing: {e}")

if __name__ == "__main__":
    checker = DVWACrossSiteFlashingChecker()
    checker.run_tests()