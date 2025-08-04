import requests
from bs4 import BeautifulSoup
import time
import datetime
from urllib.parse import urljoin
import urllib3

# Disable SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration - Make sure these URLs are correct for your DVWA installation
DVWA_BASE_URL = "http://localhost/dvwa/"
LOGIN_URL = "http://localhost/dvwa/login.php"
SECURITY_URL = "http://localhost/dvwa/security.php"
LOGOUT_URL = "http://localhost/dvwa/logout.php"
USERNAME = "admin"
PASSWORD = "password"

# Global session object
session = requests.Session()
session.verify = False  # Disable SSL verification for localhost

def get_csrf_token(url):
    """Extract CSRF token from DVWA forms"""
    try:
        response = session.get(url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Try different possible selectors for CSRF token
        token_input = soup.find('input', {'name': 'user_token'})
        if not token_input:
            token_input = soup.find('input', {'id': 'user_token'})
        if not token_input:
            # Look for any hidden input that might be the token
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
        # Get login page to extract CSRF token
        csrf_token = get_csrf_token(LOGIN_URL)
        if not csrf_token:
            return False
            
        # Perform login
        login_data = {
            'username': USERNAME,
            'password': PASSWORD,
            'Login': 'Login',
            'user_token': csrf_token
        }
        
        response = session.post(LOGIN_URL, data=login_data, allow_redirects=True, timeout=15)
        
        # Check if login was successful
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
        # First get the security page to extract CSRF token
        csrf_token = get_csrf_token(SECURITY_URL)
        if not csrf_token:
            return False
            
        security_data = {
            'security': level,
            'seclev_submit': 'Submit',
            'user_token': csrf_token
        }
        
        response = session.post(SECURITY_URL, data=security_data, timeout=15)
        
        # Check if security level was set successfully
        return level.lower() in response.text.lower() or "security level" in response.text.lower()
        
    except Exception:
        return False

def get_session_id():
    """Extract current session ID from cookies"""
    return session.cookies.get('PHPSESSID')

def test_session_fixation():
    """Test for session fixation vulnerability"""
    # Create a new session with pre-set session ID
    attacker_session = requests.Session()
    attacker_session.verify = False
    fixed_session_id = "attacker_supplied_session_id_12345"
    attacker_session.cookies.set('PHPSESSID', fixed_session_id)
    
    try:
        # Get login page to extract CSRF token with fixed session
        response = attacker_session.get(LOGIN_URL, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        if not token_input:
            token_input = soup.find('input', {'id': 'user_token'})
        if not token_input:
            # Try to find any hidden input
            hidden_inputs = soup.find_all('input', {'type': 'hidden'})
            for inp in hidden_inputs:
                if inp.get('name') and 'token' in inp.get('name', '').lower():
                    token_input = inp
                    break
        
        csrf_token = token_input['value'] if token_input and token_input.get('value') else None
        
        if not csrf_token:
            return False, "Failed to get CSRF token"
            
        # Attempt login with fixed session
        login_data = {
            'username': USERNAME,
            'password': PASSWORD,
            'Login': 'Login',
            'user_token': csrf_token
        }
        
        login_response = attacker_session.post(LOGIN_URL, data=login_data, allow_redirects=True, timeout=15)
        
        # Check if login was successful
        success_indicators = [
            "Welcome :: Damn Vulnerable Web Application",
            "dvwa_logo.png",
            "Security Level",
            "Logout"
        ]
        
        login_successful = any(indicator in login_response.text for indicator in success_indicators)
        
        if login_successful:
            # Check if session ID remained the same
            new_session_id = attacker_session.cookies.get('PHPSESSID')
            
            if new_session_id == fixed_session_id:
                return True, f"Session ID remained unchanged: {fixed_session_id}"
            else:
                return False, f"Session ID changed from {fixed_session_id} to {new_session_id}"
        else:
            return False, "Login failed"
            
    except Exception as e:
        return False, str(e)

def test_session_reuse_after_logout():
    """Test if session remains valid after logout"""
    try:
        # Get current session ID
        original_session_id = get_session_id()
        if not original_session_id:
            return False, "No valid session"
            
        # Perform logout
        session.get(LOGOUT_URL, timeout=15)
        
        # Try to access protected page with old session
        home_response = session.get(DVWA_BASE_URL, timeout=15)
        
        # Check if we're still authenticated
        success_indicators = [
            "Welcome :: Damn Vulnerable Web Application",
            "dvwa_logo.png",
            "Security Level",
            "Logout"
        ]
        
        still_authenticated = any(indicator in home_response.text for indicator in success_indicators)
        
        if still_authenticated:
            return True, f"Session {original_session_id} still active after logout"
        else:
            return False, "Session correctly invalidated"
            
    except Exception as e:
        return False, str(e)

def test_session_regeneration():
    """Test if session ID is regenerated after login/logout"""
    try:
        # Logout first to ensure clean state
        session.get(LOGOUT_URL, timeout=15)
        
        # Small delay to ensure logout is processed
        time.sleep(1)
        
        # Get new CSRF token for fresh login
        csrf_token = get_csrf_token(LOGIN_URL)
        if not csrf_token:
            return False, "Failed to get CSRF token"
            
        # Login and capture session ID
        login_data = {
            'username': USERNAME,
            'password': PASSWORD,
            'Login': 'Login',
            'user_token': csrf_token
        }
        
        session.post(LOGIN_URL, data=login_data, allow_redirects=True, timeout=15)
        session_id_after_login = get_session_id()
        
        if not session_id_after_login:
            return False, "No session ID after login"
        
        # Logout and login again
        time.sleep(1)
        session.get(LOGOUT_URL, timeout=15)
        time.sleep(1)
        
        csrf_token = get_csrf_token(LOGIN_URL)
        if csrf_token:
            login_data['user_token'] = csrf_token
            session.post(LOGIN_URL, data=login_data, allow_redirects=True, timeout=15)
            session_id_after_relogin = get_session_id()
            
            if session_id_after_relogin:
                if session_id_after_relogin != session_id_after_login:
                    return False, "Session properly regenerated"  # Not vulnerable
                else:
                    return True, f"Session ID reused: {session_id_after_login}"
            else:
                return False, "Could not verify - no session after re-login"
        else:
            return False, "Could not get CSRF token for re-login"
            
    except Exception as e:
        return False, str(e)

def generate_html_report(findings):
    """Generate OSCP-style HTML report"""
    
    # Calculate overall risk
    vulnerabilities_found = sum(1 for _, result, _ in findings if result)
    if vulnerabilities_found >= 2:
        risk_rating = "HIGH"
        risk_color = "#ff6b6b"
    elif vulnerabilities_found == 1:
        risk_rating = "MEDIUM"
        risk_color = "#ffd93d"
    else:
        risk_rating = "LOW"
        risk_color = "#6bcf7f"
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Session Management Bypass Test - OTG-SESS-001</title>
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
        .finding {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .vulnerable {{
            border-left: 4px solid #ff6b6b;
        }}
        .not-vulnerable {{
            border-left: 4px solid #6bcf7f;
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
        <h1>OWASP Testing Guide - OTG-SESS-001</h1>
        <h2>Session Management Bypass Test Report</h2>
        <div class="timestamp">Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div>Target: <a href="{DVWA_BASE_URL}" target="_blank">{DVWA_BASE_URL}</a></div>
    </div>

    <div class="summary-box">
        <h3>Executive Summary</h3>
        <p>This report details the findings of automated testing for Session Management Schema bypass vulnerabilities (OTG-SESS-001) on the DVWA application. The tests focused on identifying common session management flaws that could lead to session hijacking, fixation, or unauthorized access.</p>
        <p><strong>Risk Rating: <span class="risk-rating">{risk_rating}</span></strong></p>
        <p><strong>Vulnerabilities Found: {vulnerabilities_found}</strong></p>
    </div>

    <h2>Test Details</h2>
    <h3>Methodology</h3>
    <p>The following tests were conducted:</p>
    <ul>
        <li>Session Fixation Testing</li>
        <li>Session Reuse After Logout</li>
        <li>Session Regeneration Verification</li>
    </ul>
    <p>All tests were performed against DVWA configured at security level 'Low'.</p>

    <h3>Findings</h3>"""
    
    for test_name, is_vulnerable, details in findings:
        status = "VULNERABLE" if is_vulnerable else "NOT VULNERABLE"
        css_class = "vulnerable" if is_vulnerable else "not-vulnerable"
        html_content += f"""
    <div class="finding {css_class}">
        <h3>{test_name}</h3>
        <p><strong>Status:</strong> {status}</p>
        <p><strong>Details:</strong> {details}</p>
    </div>"""
    
    html_content += f"""
    <div class="recommendations">
        <h3>Remediation Recommendations</h3>
        <ul>
            <li>Always regenerate session IDs after successful authentication</li>
            <li>Invalidate session tokens upon logout</li>
            <li>Implement secure session management practices as per OWASP guidelines</li>
            <li>Use secure, HttpOnly, and SameSite cookie attributes</li>
            <li>Implement proper session timeout mechanisms</li>
        </ul>
    </div>

    <div class="references">
        <h3>References</h3>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema" target="_blank">OWASP Testing Guide - OTG-SESS-001</a></li>
            <li><a href="https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet" target="_blank">OWASP Session Management Cheat Sheet</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/384.html" target="_blank">CWE-384: Session Fixation</a></li>
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
    print("[*] Starting Session Management Bypass Test (OTG-SESS-001)")
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
    
    # Run tests
    findings = []
    
    # Test 1: Session Fixation
    is_vuln, details = test_session_fixation()
    findings.append(("Session Fixation Test", is_vuln, details))
    
    # Test 2: Session Reuse After Logout
    is_vuln, details = test_session_reuse_after_logout()
    findings.append(("Session Reuse After Logout", is_vuln, details))
    
    # Test 3: Session Regeneration
    is_vuln, details = test_session_regeneration()
    findings.append(("Session Regeneration Test", is_vuln, details))
    
    # Generate HTML report
    html_report = generate_html_report(findings)
    
    try:
        with open("OTG-SESS-001_Session_Bypass_Report.html", "w", encoding="utf-8") as f:
            f.write(html_report)
        print("[+] HTML report saved as 'OTG-SESS-001_Session_Bypass_Report.html'")
    except Exception as e:
        print(f"[-] Failed to save HTML report: {str(e)}")
    
    # Print summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    vulnerabilities_found = 0
    for test_name, is_vuln, details in findings:
        status = "VULNERABLE" if is_vuln else "NOT VULNERABLE"
        print(f"{test_name}: {status}")
        if is_vuln:
            vulnerabilities_found += 1
    
    print(f"\nTotal Vulnerabilities Found: {vulnerabilities_found}")
    print("Report saved to: OTG-SESS-001_Session_Bypass_Report.html")
    print("="*50)

if __name__ == "__main__":
    main()