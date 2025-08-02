import requests
from bs4 import BeautifulSoup
import datetime
from urllib.parse import urljoin
import urllib3

# Disable SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
DVWA_BASE_URL = "http://localhost/dvwa/"
LOGIN_URL = "http://localhost/dvwa/login.php"
SECURITY_URL = "http://localhost/dvwa/security.php"
LOGOUT_URL = "http://localhost/dvwa/logout.php"
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

def get_session_id():
    """Extract current session ID from cookies"""
    return session.cookies.get('PHPSESSID')

def test_session_fixation():
    """Test for session fixation vulnerability"""
    findings = {
        'vulnerable': False,
        'details': '',
        'session_ids': {},
        'test_steps': []
    }
    
    # Step 1: Create attacker session with fixed session ID
    attacker_session = requests.Session()
    attacker_session.verify = False
    fixed_session_id = "session_fixation_test_12345"
    attacker_session.cookies.set('PHPSESSID', fixed_session_id)
    
    findings['session_ids']['fixed'] = fixed_session_id
    findings['test_steps'].append("1. Set fixed session ID in attacker session")
    
    try:
        # Step 2: Get CSRF token with fixed session
        response = attacker_session.get(LOGIN_URL, timeout=15)
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
        
        csrf_token = token_input['value'] if token_input and token_input.get('value') else None
        
        if not csrf_token:
            findings['details'] = "Failed to get CSRF token for fixed session"
            return findings
            
        findings['test_steps'].append("2. Retrieved CSRF token with fixed session")
        
        # Step 3: Attempt login with fixed session
        login_data = {
            'username': USERNAME,
            'password': PASSWORD,
            'Login': 'Login',
            'user_token': csrf_token
        }
        
        login_response = attacker_session.post(LOGIN_URL, data=login_data, allow_redirects=True, timeout=15)
        
        # Step 4: Check if login was successful
        success_indicators = [
            "Welcome :: Damn Vulnerable Web Application",
            "dvwa_logo.png",
            "Security Level",
            "Logout"
        ]
        
        login_successful = any(indicator in login_response.text for indicator in success_indicators)
        
        if login_successful:
            # Step 5: Check if session ID remained the same
            new_session_id = attacker_session.cookies.get('PHPSESSID')
            findings['session_ids']['after_login'] = new_session_id if new_session_id else "None"
            
            if new_session_id == fixed_session_id:
                findings['vulnerable'] = True
                findings['details'] = f"VULNERABLE: Session fixation detected - Session ID was not regenerated (remains {fixed_session_id})"
                findings['test_steps'].append("3. Login successful with fixed session")
                findings['test_steps'].append(f"4. Session ID unchanged after login: {fixed_session_id}")
            else:
                findings['details'] = f"NOT VULNERABLE: Session ID was regenerated ({fixed_session_id} -> {new_session_id})"
                findings['test_steps'].append("3. Login successful")
                findings['test_steps'].append(f"4. Session ID regenerated: {fixed_session_id} -> {new_session_id}")
        else:
            findings['details'] = "Login failed with fixed session"
            findings['test_steps'].append("3. Login failed with fixed session")
            
    except Exception as e:
        findings['details'] = f"Error during session fixation test: {str(e)}"
        findings['test_steps'].append(f"3. Error occurred: {str(e)}")
    
    return findings

def test_additional_session_scenarios():
    """Test additional session management scenarios"""
    scenarios = []
    
    try:
        # Scenario 1: Session reuse after logout
        original_session_id = get_session_id()
        if original_session_id:
            # Logout
            session.get(LOGOUT_URL, timeout=15)
            # Try to access with old session
            response = session.get(DVWA_BASE_URL, timeout=15)
            success_indicators = [
                "Welcome :: Damn Vulnerable Web Application",
                "dvwa_logo.png",
                "Security Level",
                "Logout"
            ]
            still_authenticated = any(indicator in response.text for indicator in success_indicators)
            
            scenarios.append({
                'name': 'Session Reuse After Logout',
                'vulnerable': still_authenticated,
                'details': f"Session {'still valid' if still_authenticated else 'properly invalidated'} after logout"
            })
        
        # Scenario 2: Session regeneration on re-login
        # Login again
        if login():
            new_session_id = get_session_id()
            if new_session_id and new_session_id != original_session_id:
                scenarios.append({
                    'name': 'Session Regeneration on Re-login',
                    'vulnerable': False,
                    'details': f"Session properly regenerated ({original_session_id} -> {new_session_id})"
                })
            elif new_session_id:
                scenarios.append({
                    'name': 'Session Regeneration on Re-login',
                    'vulnerable': True,
                    'details': f"Session not regenerated (still {new_session_id})"
                })
                
    except Exception as e:
        scenarios.append({
            'name': 'Additional Scenarios',
            'vulnerable': False,
            'details': f"Error in additional tests: {str(e)}"
        })
    
    return scenarios

def generate_html_report(main_finding, additional_scenarios):
    """Generate OSCP-style HTML report"""
    
    # Calculate overall risk
    is_vulnerable = main_finding['vulnerable'] or any(s['vulnerable'] for s in additional_scenarios)
    
    if is_vulnerable:
        risk_rating = "HIGH"
        risk_color = "#ff6b6b"
        cvss_score = "7.5 (High)"
    else:
        risk_rating = "LOW"
        risk_color = "#6bcf7f"
        cvss_score = "2.5 (Low)"
    
    # Generate test steps HTML
    steps_html = "<ol>"
    for step in main_finding['test_steps']:
        steps_html += f"<li>{step}</li>"
    steps_html += "</ol>"
    
    # Generate session IDs table
    session_table = "<table><tr><th>Phase</th><th>Session ID</th></tr>"
    for phase, sid in main_finding['session_ids'].items():
        session_table += f"<tr><td>{phase.capitalize()}</td><td>{sid}</td></tr>"
    session_table += "</table>"
    
    # Generate additional scenarios HTML
    scenarios_html = ""
    for scenario in additional_scenarios:
        status = "VULNERABLE" if scenario['vulnerable'] else "NOT VULNERABLE"
        status_class = "fail" if scenario['vulnerable'] else "pass"
        scenarios_html += f"""
        <div class="scenario">
            <h4>{scenario['name']}</h4>
            <p><strong>Status:</strong> <span class="{status_class}">{status}</span></p>
            <p><strong>Details:</strong> {scenario['details']}</p>
        </div>"""
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Session Fixation Test - OTG-SESS-003</title>
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
        .scenario {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .risk-rating {{
            display: inline-block;
            padding: 5px 10px;
            font-weight: bold;
            background-color: {risk_color};
            color: #000;
        }}
        .cvss-score {{
            display: inline-block;
            padding: 5px 10px;
            font-weight: bold;
            background-color: #9cdcfe;
            color: #000;
        }}
        .pass {{
            color: #6bcf7f;
        }}
        .fail {{
            color: #ff6b6b;
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
        h2, h3, h4 {{
            color: #569cd6;
        }}
        .timestamp {{
            color: #9cdcfe;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #1e1e1e;
            margin: 15px 0;
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
        ol {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        li {{
            margin: 5px 0;
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
        <h1>OWASP Testing Guide - OTG-SESS-003</h1>
        <h2>Session Fixation Test Report</h2>
        <div class="timestamp">Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div>Target: <a href="{DVWA_BASE_URL}" target="_blank">{DVWA_BASE_URL}</a></div>
    </div>

    <div class="summary-box">
        <h3>Executive Summary</h3>
        <p>This report details the findings of automated testing for Session Fixation vulnerabilities (OTG-SESS-003) on the DVWA application. Session fixation is a web application vulnerability where an attacker can force a victim to use a known session identifier, potentially allowing the attacker to hijack the victim's session after they authenticate.</p>
        <p><strong>Risk Rating: <span class="risk-rating">{risk_rating}</span></strong></p>
        <p><strong>CVSS Score: <span class="cvss-score">{cvss_score}</span></strong></p>
    </div>

    <h2>Test Details</h2>
    <h3>Methodology</h3>
    <p>The following methodology was used to test for session fixation:</p>
    {steps_html}

    <h3>Session ID Analysis</h3>
    {session_table}

    <h3>Main Finding</h3>
    <div class="finding {'vulnerable' if main_finding['vulnerable'] else 'not-vulnerable'}">
        <h3>Session Fixation Test</h3>
        <p><strong>Status:</strong> <span class="{'fail' if main_finding['vulnerable'] else 'pass'}">{'VULNERABLE' if main_finding['vulnerable'] else 'NOT VULNERABLE'}</span></p>
        <p><strong>Details:</strong> {main_finding['details']}</p>
    </div>

    <h3>Additional Session Management Tests</h3>
    {scenarios_html}

    <div class="recommendations">
        <h3>Remediation Recommendations</h3>
        <ul>
            <li>Always regenerate session IDs after successful authentication</li>
            <li>Destroy old session data when regenerating session IDs</li>
            <li>Implement proper session invalidation upon logout</li>
            <li>Use secure session management libraries and frameworks</li>
            <li>Set appropriate session timeout values</li>
            <li>Consider implementing additional session validation mechanisms</li>
        </ul>
        <h4>Secure Implementation Example:</h4>
        <pre>// PHP example
session_start();
// Regenerate session ID on login
session_regenerate_id(true);
// Destroy session on logout
session_destroy();</pre>
    </div>

    <div class="references">
        <h3>References</h3>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation" target="_blank">OWASP Testing Guide - OTG-SESS-003</a></li>
            <li><a href="https://owasp.org/www-community/attacks/Session_fixation" target="_blank">OWASP Session Fixation Attack</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/384.html" target="_blank">CWE-384: Session Fixation</a></li>
            <li><a href="https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet" target="_blank">OWASP Session Management Cheat Sheet</a></li>
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
    print("[*] Starting Session Fixation Test (OTG-SESS-003)")
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
    
    # Test session fixation
    print("[*] Testing session fixation vulnerability...")
    main_finding = test_session_fixation()
    
    # Test additional scenarios
    print("[*] Testing additional session management scenarios...")
    additional_scenarios = test_additional_session_scenarios()
    
    # Generate HTML report
    print("[*] Generating HTML report...")
    html_report = generate_html_report(main_finding, additional_scenarios)
    
    try:
        with open("OTG-SESS-003_Session_Fixation_Report.html", "w", encoding="utf-8") as f:
            f.write(html_report)
        print("[+] HTML report saved as 'OTG-SESS-003_Session_Fixation_Report.html'")
    except Exception as e:
        print(f"[-] Failed to save HTML report: {str(e)}")
    
    # Print summary
    print("\n" + "="*50)
    print("SESSION FIXATION TEST SUMMARY")
    print("="*50)
    print(f"Main Test: {'VULNERABLE' if main_finding['vulnerable'] else 'NOT VULNERABLE'}")
    print(f"Details: {main_finding['details']}")
    
    print("\nAdditional Scenarios:")
    for scenario in additional_scenarios:
        status = "VULNERABLE" if scenario['vulnerable'] else "NOT VULNERABLE"
        print(f"  {scenario['name']}: {status}")
        print(f"    Details: {scenario['details']}")
    
    print(f"\nReport saved to: OTG-SESS-003_Session_Fixation_Report.html")
    print("="*50)

if __name__ == "__main__":
    main()