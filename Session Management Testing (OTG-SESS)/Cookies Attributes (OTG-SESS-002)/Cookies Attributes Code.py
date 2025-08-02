import requests
from bs4 import BeautifulSoup
import datetime
from urllib.parse import urlparse
import urllib3

# Disable SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
DVWA_BASE_URL = "http://localhost/dvwa/"
LOGIN_URL = "http://localhost/dvwa/login.php"
SECURITY_URL = "http://localhost/dvwa/security.php"
USERNAME = "admin"
PASSWORD = "password"

# Global session object
session = requests.Session()
session.verify = False

def get_csrf_token(url):
    """Extract CSRF token from DVWA forms"""
    try:
        response = session.get(url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        token_input = soup.find('input', {'name': 'user_token'})
        if not token_input:
            token_input = soup.find('input', {'id': 'user_token'})
        if not token_input:
            hidden_inputs = soup.find_all('input', {'type': 'hidden'})
            for inp in hidden_inputs:
                if inp.get('name') and 'token' in inp.get('name', '').lower():
                    token_input = inp
                    break
                elif inp.get('id') and 'token' in inp.get('id', '').lower():
                    token_input = inp
                    break
        
        if token_input and token_input.get('value'):
            return token_input['value']
        else:
            return None
    except Exception:
        return None

def login():
    """Login to DVWA and return success status"""
    try:
        csrf_token = get_csrf_token(LOGIN_URL)
        if not csrf_token:
            return False
            
        login_data = {
            'username': USERNAME,
            'password': PASSWORD,
            'Login': 'Login',
            'user_token': csrf_token
        }
        
        response = session.post(LOGIN_URL, data=login_data, allow_redirects=True, timeout=15)
        
        success_indicators = [
            "Welcome :: Damn Vulnerable Web Application",
            "dvwa_logo.png",
            "Security Level",
            "Logout"
        ]
        
        return any(indicator in response.text for indicator in success_indicators)
    except Exception:
        return False

def set_security_level(level='low'):
    """Set DVWA security level"""
    try:
        csrf_token = get_csrf_token(SECURITY_URL)
        if not csrf_token:
            return False
            
        security_data = {
            'security': level,
            'seclev_submit': 'Submit',
            'user_token': csrf_token
        }
        
        response = session.post(SECURITY_URL, data=security_data, timeout=15)
        return level.lower() in response.text.lower() or "security level" in response.text.lower()
    except Exception:
        return False

def analyze_cookies():
    """Analyze cookie attributes for security issues"""
    cookie_findings = []
    
    # Get cookies from session
    cookies = session.cookies
    
    for cookie_name, cookie_value in cookies.items():
        cookie_obj = cookies._cookies.get(list(cookies._cookies.keys())[0]).get('/').get(cookie_name)
        
        finding = {
            'name': cookie_name,
            'value': cookie_value[:30] + '...' if len(cookie_value) > 30 else cookie_value,
            'attributes': {}
        }
        
        # Check Secure attribute
        secure = hasattr(cookie_obj, 'secure') and cookie_obj.secure
        finding['attributes']['Secure'] = {
            'value': secure,
            'expected': urlparse(DVWA_BASE_URL).scheme == 'https',
            'status': 'PASS' if secure == (urlparse(DVWA_BASE_URL).scheme == 'https') else 'FAIL',
            'risk': 'Medium' if not secure and urlparse(DVWA_BASE_URL).scheme == 'https' else 'Low'
        }
        
        # Check HttpOnly attribute
        httponly = hasattr(cookie_obj, 'httponly') and cookie_obj.httponly
        finding['attributes']['HttpOnly'] = {
            'value': httponly,
            'expected': True,
            'status': 'PASS' if httponly else 'FAIL',
            'risk': 'High' if not httponly else 'Low'
        }
        
        # Check SameSite attribute
        samesite = getattr(cookie_obj, 'samesite', None)
        finding['attributes']['SameSite'] = {
            'value': samesite if samesite else 'Not Set',
            'expected': 'Strict or Lax',
            'status': 'PASS' if samesite in ['Strict', 'Lax'] else 'FAIL',
            'risk': 'Medium' if not samesite else 'Low'
        }
        
        # Check Domain attribute
        domain = getattr(cookie_obj, 'domain', None)
        finding['attributes']['Domain'] = {
            'value': domain if domain else 'Not Set',
            'expected': 'Valid domain',
            'status': 'PASS' if domain else 'INFO',
            'risk': 'Low'
        }
        
        # Check Path attribute
        path = getattr(cookie_obj, 'path', None)
        finding['attributes']['Path'] = {
            'value': path if path else 'Not Set',
            'expected': 'Appropriate path',
            'status': 'INFO',
            'risk': 'Low'
        }
        
        # Check Expires/Max-Age
        expires = getattr(cookie_obj, 'expires', None)
        finding['attributes']['Expires/Max-Age'] = {
            'value': 'Session' if not expires else str(expires),
            'expected': 'Session for session cookies',
            'status': 'INFO',
            'risk': 'Low'
        }
        
        cookie_findings.append(finding)
    
    return cookie_findings

def generate_html_report(findings):
    """Generate OSCP-style HTML report"""
    
    # Calculate overall risk
    high_risk = sum(1 for cookie in findings for attr in cookie['attributes'].values() if attr['risk'] == 'High')
    medium_risk = sum(1 for cookie in findings for attr in cookie['attributes'].values() if attr['risk'] == 'Medium')
    
    if high_risk > 0:
        risk_rating = "HIGH"
        risk_color = "#ff6b6b"
    elif medium_risk > 0:
        risk_rating = "MEDIUM"
        risk_color = "#ffd93d"
    else:
        risk_rating = "LOW"
        risk_color = "#6bcf7f"
    
    # Generate cookie table HTML
    cookie_tables = ""
    for cookie in findings:
        cookie_tables += f"""
    <div class="cookie-table">
        <h3>Cookie: {cookie['name']}</h3>
        <table>
            <tr>
                <th>Attribute</th>
                <th>Value</th>
                <th>Expected</th>
                <th>Status</th>
                <th>Risk</th>
            </tr>"""
        
        for attr_name, attr_data in cookie['attributes'].items():
            status_class = "pass" if attr_data['status'] == 'PASS' else ("fail" if attr_data['status'] == 'FAIL' else "info")
            cookie_tables += f"""
            <tr>
                <td>{attr_name}</td>
                <td>{attr_data['value']}</td>
                <td>{attr_data['expected']}</td>
                <td class="{status_class}">{attr_data['status']}</td>
                <td>{attr_data['risk']}</td>
            </tr>"""
        
        cookie_tables += """
        </table>
    </div>"""
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Cookie Attributes Test - OTG-SESS-002</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #1e1e1e;
            color: #d4d4d4;
            margin: 0;
            padding: 20px;
        }}
        .header {{
            background-color: #252526;
            padding: 20px;
            border-left: 4px solid #569cd6;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0;
            color: #569cd6;
            font-size: 24px;
        }}
        .summary-box {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .cookie-table {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .cookie-table h3 {{
            color: #569cd6;
            margin-top: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #1e1e1e;
        }}
        th, td {{
            border: 1px solid #3c3c3c;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #252526;
            color: #569cd6;
        }}
        .pass {{
            color: #6bcf7f;
        }}
        .fail {{
            color: #ff6b6b;
        }}
        .info {{
            color: #9cdcfe;
        }}
        .risk-rating {{
            display: inline-block;
            padding: 5px 10px;
            font-weight: bold;
            background-color: {risk_color};
            color: #000;
        }}
        .recommendations {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin-top: 20px;
        }}
        .references {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin-top: 20px;
            font-size: 12px;
        }}
        h2, h3 {{
            color: #569cd6;
        }}
        .timestamp {{
            color: #9cdcfe;
            font-size: 14px;
        }}
        pre {{
            background-color: #1e1e1e;
            border: 1px solid #3c3c3c;
            padding: 10px;
            overflow-x: auto;
        }}
        a {{
            color: #569cd6;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP Testing Guide - OTG-SESS-002</h1>
        <h2>Cookie Attributes Test Report</h2>
        <div class="timestamp">Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div>Target: <a href="{DVWA_BASE_URL}" target="_blank">{DVWA_BASE_URL}</a></div>
    </div>

    <div class="summary-box">
        <h3>Executive Summary</h3>
        <p>This report details the findings of automated testing for Cookie Attributes (OTG-SESS-002) on the DVWA application. The tests focused on analyzing the security attributes of cookies set by the application to identify potential vulnerabilities that could lead to session hijacking, cross-site scripting, or cross-site request forgery attacks.</p>
        <p><strong>Risk Rating: <span class="risk-rating">{risk_rating}</span></strong></p>
        <p><strong>Cookies Analyzed: {len(findings)}</strong></p>
    </div>

    <h2>Test Details</h2>
    <h3>Methodology</h3>
    <p>The following tests were conducted:</p>
    <ul>
        <li>Cookie attribute analysis (Secure, HttpOnly, SameSite, Domain, Path, Expires)</li>
        <li>Risk assessment based on missing or improper cookie attributes</li>
        <li>Evaluation of session management cookies</li>
    </ul>
    <p>All tests were performed against DVWA configured at security level 'Low'.</p>

    <h3>Cookie Analysis</h3>
    {cookie_tables}

    <div class="recommendations">
        <h3>Remediation Recommendations</h3>
        <ul>
            <li>Set the HttpOnly flag on all session cookies to prevent XSS attacks</li>
            <li>Set the Secure flag on cookies when using HTTPS</li>
            <li>Set the SameSite attribute to 'Strict' or 'Lax' to prevent CSRF attacks</li>
            <li>Use appropriate Domain and Path attributes to limit cookie scope</li>
            <li>Ensure session cookies are set as session cookies (no persistent storage)</li>
            <li>Regularly audit cookie attributes during security reviews</li>
        </ul>
    </div>

    <div class="references">
        <h3>References</h3>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes" target="_blank">OWASP Testing Guide - OTG-SESS-002</a></li>
            <li><a href="https://owasp.org/www-community/controls/SecureCookieAttribute" target="_blank">OWASP Secure Cookie Attributes</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/1004.html" target="_blank">CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/79.html" target="_blank">CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')</a></li>
        </ul>
    </div>
</body>
</html>"""
    
    return html_content

def check_dvwa_accessibility():
    """Check if DVWA is accessible"""
    try:
        response = session.get(DVWA_BASE_URL, timeout=15)
        return response.status_code == 200 and ("Damn Vulnerable Web App" in response.text or "login" in response.text.lower())
    except Exception:
        return False

def main():
    """Main execution function"""
    print("[*] Starting Cookie Attributes Test (OTG-SESS-002)")
    print(f"[*] Target: {DVWA_BASE_URL}")
    
    # Check if DVWA is accessible
    if not check_dvwa_accessibility():
        print("[-] Exiting due to DVWA inaccessibility")
        return
    
    # Login to DVWA
    if not login():
        print("[-] Exiting due to login failure")
        return
    
    # Set security level to low
    set_security_level('low')
    
    # Analyze cookies
    print("[*] Analyzing cookie attributes...")
    findings = analyze_cookies()
    
    # Generate HTML report
    print("[*] Generating HTML report...")
    html_report = generate_html_report(findings)
    
    try:
        with open("OTG-SESS-002_Cookie_Attributes_Report.html", "w", encoding="utf-8") as f:
            f.write(html_report)
        print("[+] HTML report saved as 'OTG-SESS-002_Cookie_Attributes_Report.html'")
    except Exception as e:
        print(f"[-] Failed to save HTML report: {str(e)}")
    
    # Print summary
    print("\n" + "="*50)
    print("COOKIE ANALYSIS SUMMARY")
    print("="*50)
    
    high_risk = 0
    medium_risk = 0
    low_risk = 0
    
    for cookie in findings:
        print(f"\nCookie: {cookie['name']}")
        for attr_name, attr_data in cookie['attributes'].items():
            print(f"  {attr_name}: {attr_data['status']} ({attr_data['risk']} risk)")
            if attr_data['risk'] == 'High':
                high_risk += 1
            elif attr_data['risk'] == 'Medium':
                medium_risk += 1
            else:
                low_risk += 1
    
    print(f"\nTotal Issues Found: {high_risk + medium_risk}")
    print(f"  High Risk: {high_risk}")
    print(f"  Medium Risk: {medium_risk}")
    print(f"  Low Risk: {low_risk}")
    print("Report saved to: OTG-SESS-002_Cookie_Attributes_Report.html")
    print("="*50)

if __name__ == "__main__":
    main()