import requests
from bs4 import BeautifulSoup
import datetime
import urllib3
from urllib.parse import urljoin
import time

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
    except Exception as e:
        print(f"[-] Error getting CSRF token from {url}: {str(e)}")
        return None

def login():
    """Login to DVWA and return success status"""
    try:
        print("[+] Attempting to login to DVWA")
        csrf_token = get_csrf_token(LOGIN_URL)
        if not csrf_token:
            print("[-] Failed to get CSRF token for login")
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
        
        is_logged_in = any(indicator in response.text for indicator in success_indicators)
        if is_logged_in:
            print("[+] Successfully logged in to DVWA")
        else:
            print("[-] Login failed")
        return is_logged_in
    except Exception as e:
        print(f"[-] Error during login: {str(e)}")
        return False

def get_current_security_level():
    """Get current DVWA security level"""
    try:
        response = session.get(SECURITY_URL, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for selected security level
        selected_option = soup.find('option', {'selected': True})
        if selected_option:
            return selected_option.get('value', 'unknown')
        return 'unknown'
    except Exception as e:
        print(f"[-] Error getting current security level: {str(e)}")
        return 'unknown'

def set_security_level(level='low'):
    """Set DVWA security level with better error handling"""
    try:
        print(f"[+] Setting security level to {level}")
        
        # Get current page to extract CSRF token
        response = session.get(SECURITY_URL, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find CSRF token
        token_input = soup.find('input', {'name': 'user_token'})
        if not token_input:
            token_input = soup.find('input', {'id': 'user_token'})
        
        if not token_input or not token_input.get('value'):
            print("[-] Failed to find CSRF token on security page")
            return False
            
        csrf_token = token_input['value']
        print(f"[+] Found CSRF token: {csrf_token[:20]}...")
        
        security_data = {
            'security': level,
            'seclev_submit': 'Submit',
            'user_token': csrf_token
        }
        
        # Submit the form
        response = session.post(SECURITY_URL, data=security_data, timeout=15)
        
        # Check if security level was set successfully
        time.sleep(1)  # Give it a moment to process
        current_level = get_current_security_level()
        
        if current_level.lower() == level.lower():
            print(f"[+] Successfully set security level to {level}")
            return True
        else:
            print(f"[-] Failed to set security level to {level}. Current level: {current_level}")
            return False
            
    except Exception as e:
        print(f"[-] Error setting security level to {level}: {str(e)}")
        return False

def get_session_id():
    """Extract current session ID from cookies"""
    session_id = session.cookies.get('PHPSESSID')
    return session_id

def is_authenticated():
    """Check if current session is authenticated"""
    try:
        response = session.get(DVWA_BASE_URL, timeout=15)
        success_indicators = [
            "Welcome :: Damn Vulnerable Web Application",
            "dvwa_logo.png",
            "Security Level",
            "Logout"
        ]
        return any(indicator in response.text for indicator in success_indicators)
    except Exception as e:
        print(f"[-] Error checking authentication status: {str(e)}")
        return False

def test_logout_functionality():
    """Test logout functionality comprehensively"""
    findings = {
        'session_id_before': None,
        'session_id_after': None,
        'authenticated_before': False,
        'authenticated_after': False,
        'redirects_to_login': False,
        'vulnerable': False,
        'details': [],
        'test_steps': []
    }
    
    try:
        print("[+] Testing logout functionality")
        
        # Step 1: Record session state before logout
        findings['session_id_before'] = get_session_id()
        findings['authenticated_before'] = is_authenticated()
        findings['test_steps'].append("1. Recorded session state before logout")
        
        print(f"[+] Session ID before logout: {findings['session_id_before']}")
        print(f"[+] Authenticated before logout: {findings['authenticated_before']}")
        
        if not findings['authenticated_before']:
            findings['details'].append("ERROR: Not authenticated before logout test")
            print("[-] Not authenticated before logout test")
            return findings
        
        # Step 2: Perform logout
        print("[+] Performing logout")
        logout_response = session.get(LOGOUT_URL, allow_redirects=True, timeout=15)
        findings['test_steps'].append("2. Performed logout request")
        
        # Step 3: Check if redirected to login page
        if "login" in logout_response.url.lower() or "login" in logout_response.text.lower():
            findings['redirects_to_login'] = True
            findings['test_steps'].append("3. Confirmed redirection to login page")
            print("[+] Confirmed redirection to login page")
        else:
            findings['test_steps'].append("3. No redirection to login page detected")
            print("[-] No redirection to login page detected")
        
        # Step 4: Record session state after logout
        findings['session_id_after'] = get_session_id()
        findings['authenticated_after'] = is_authenticated()
        findings['test_steps'].append("4. Recorded session state after logout")
        
        print(f"[+] Session ID after logout: {findings['session_id_after']}")
        print(f"[+] Authenticated after logout: {findings['authenticated_after']}")
        
        # Step 5: Analyze results
        if findings['authenticated_after']:
            findings['vulnerable'] = True
            findings['details'].append("VULNERABLE: Session still valid after logout")
            print("[!] VULNERABLE: Session still valid after logout")
        else:
            findings['details'].append("NOT VULNERABLE: Session properly invalidated after logout")
            print("[+] NOT VULNERABLE: Session properly invalidated after logout")
            
        if not findings['redirects_to_login']:
            findings['details'].append("WARNING: No redirection to login page after logout")
            print("[-] WARNING: No redirection to login page after logout")
            
        # Step 6: Test session reuse (try to use old session)
        if findings['session_id_before']:
            print("[+] Testing session reuse with old session ID")
            reuse_session = requests.Session()
            reuse_session.verify = False
            reuse_session.cookies.set('PHPSESSID', findings['session_id_before'])
            
            reuse_response = reuse_session.get(DVWA_BASE_URL, timeout=15)
            success_indicators = [
                "Welcome :: Damn Vulnerable Web Application",
                "dvwa_logo.png",
                "Security Level",
                "Logout"
            ]
            session_reused = any(indicator in reuse_response.text for indicator in success_indicators)
            
            if session_reused:
                findings['vulnerable'] = True
                findings['details'].append("VULNERABLE: Old session ID can still be used")
                print("[!] VULNERABLE: Old session ID can still be used")
            else:
                findings['details'].append("NOT VULNERABLE: Old session ID properly invalidated")
                print("[+] NOT VULNERABLE: Old session ID properly invalidated")
                
            findings['test_steps'].append("5. Tested reuse of old session ID")
            
    except Exception as e:
        error_msg = f"ERROR during logout test: {str(e)}"
        findings['details'].append(error_msg)
        print(f"[-] {error_msg}")
    
    return findings

def test_logout_at_security_level(level):
    """Test logout functionality at specific security level"""
    result = {
        'security_level': level,
        'findings': None,
        'error': None
    }
    
    try:
        print(f"\n[+] Testing logout functionality at {level} security level")
        
        # Login first
        if not login():
            result['error'] = f"Failed to login at {level} security level"
            print(f"[-] {result['error']}")
            return result
        
        # Set security level
        if not set_security_level(level):
            result['error'] = f"Failed to set security level to {level}"
            print(f"[-] {result['error']}")
            return result
        
        # Verify security level was set
        current_level = get_current_security_level()
        print(f"[+] Current security level: {current_level}")
        
        # Test logout
        findings = test_logout_functionality()
        result['findings'] = findings
        
    except Exception as e:
        result['error'] = f"Error testing {level} security level: {str(e)}"
        print(f"[-] {result['error']}")
    
    return result

def test_cached_page_access():
    """Test if cached pages can be accessed after logout"""
    findings = {
        'can_access_cached': False,
        'details': ''
    }
    
    try:
        print("[+] Testing cached page access after logout")
        
        # Login
        if not login():
            findings['details'] = "Failed to login for cache test"
            print("[-] Failed to login for cache test")
            return findings
        
        # Visit a few pages to potentially cache them
        pages = [
            DVWA_BASE_URL,
            "http://localhost/dvwa/instructions.php",
            "http://localhost/dvwa/security.php"
        ]
        
        print("[+] Visiting pages to potentially cache them")
        for page in pages:
            try:
                session.get(page, timeout=15)
                print(f"[+] Visited {page}")
            except Exception as e:
                print(f"[-] Error visiting {page}: {str(e)}")
        
        # Logout
        print("[+] Logging out")
        session.get(LOGOUT_URL, timeout=15)
        
        # Try to access cached pages
        print("[+] Testing access to cached pages after logout")
        for page in pages:
            try:
                response = session.get(page, timeout=15)
                if is_authenticated():
                    findings['can_access_cached'] = True
                    findings['details'] = f"Can access cached page: {page}"
                    print(f"[!] VULNERABLE: Can access cached page {page}")
                    break
                else:
                    print(f"[-] Cannot access {page} (properly blocked)")
            except Exception as e:
                print(f"[-] Error accessing {page}: {str(e)}")
                continue
                
        if not findings['can_access_cached']:
            findings['details'] = "Cannot access cached pages after logout"
            print("[+] NOT VULNERABLE: Cannot access cached pages after logout")
            
    except Exception as e:
        error_msg = f"Error in cache test: {str(e)}"
        findings['details'] = error_msg
        print(f"[-] {error_msg}")
    
    return findings

def generate_html_report(test_results, cache_test_result):
    """Generate OSCP-style HTML report"""
    
    # Calculate overall risk
    vulnerable_count = sum(1 for result in test_results if result['findings'] and result['findings']['vulnerable'])
    
    if vulnerable_count > 0:
        risk_rating = "HIGH"
        risk_color = "#ff6b6b"
        cvss_score = "7.4 (High)"
    else:
        risk_rating = "LOW"
        risk_color = "#6bcf7f"
        cvss_score = "2.0 (Low)"
    
    # Generate test results HTML
    results_html = ""
    
    for result in test_results:
        results_html += f"""
        <div class="security-level">
            <h3>Security Level: {result['security_level'].capitalize()}</h3>"""
        
        if result['error']:
            results_html += f"""
            <div class="finding error">
                <p><strong>Error:</strong> {result['error']}</p>
            </div>"""
        elif result['findings']:
            findings = result['findings']
            status_class = "fail" if findings['vulnerable'] else "pass"
            status_text = "VULNERABLE" if findings['vulnerable'] else "NOT VULNERABLE"
            
            results_html += f"""
            <div class="finding">
                <p><strong>Status:</strong> <span class="{status_class}">{status_text}</span></p>
                <p><strong>Session ID Before:</strong> {findings['session_id_before'] or 'None'}</p>
                <p><strong>Session ID After:</strong> {findings['session_id_after'] or 'None'}</p>
                <p><strong>Authenticated Before:</strong> {findings['authenticated_before']}</p>
                <p><strong>Authenticated After:</strong> {findings['authenticated_after']}</p>
                <p><strong>Redirects to Login:</strong> {findings['redirects_to_login']}</p>
                <div class="details">
                    <strong>Details:</strong>
                    <ul>"""
            
            for detail in findings['details']:
                results_html += f"<li>{detail}</li>"
            
            results_html += """
                    </ul>
                </div>
            </div>"""
        
        results_html += "</div>"
    
    # Add cache test results
    cache_status_class = "fail" if cache_test_result['can_access_cached'] else "pass"
    cache_status_text = "VULNERABLE" if cache_test_result['can_access_cached'] else "NOT VULNERABLE"
    
    cache_html = f"""
        <div class="cache-test">
            <h3>Cache Access After Logout Test</h3>
            <div class="finding">
                <p><strong>Status:</strong> <span class="{cache_status_class}">{cache_status_text}</span></p>
                <p><strong>Details:</strong> {cache_test_result['details']}</p>
            </div>
        </div>"""
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Logout Functionality Test - OTG-SESS-006</title>
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
        .security-level, .cache-test {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .finding {{
            background-color: #1e1e1e;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin: 15px 0;
        }}
        .finding.error {{
            border-left: 4px solid #ff6b6b;
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
        h2, h3 {{
            color: #569cd6;
        }}
        .timestamp {{
            color: #9cdcfe;
            font-size: 14px;
        }}
        ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        li {{
            margin: 5px 0;
        }}
        .details ul {{
            margin-top: 5px;
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
        <h1>OWASP Testing Guide - OTG-SESS-006</h1>
        <h2>Logout Functionality Test Report</h2>
        <div class="timestamp">Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div>Target: <a href="{DVWA_BASE_URL}" target="_blank">{DVWA_BASE_URL}</a></div>
    </div>

    <div class="summary-box">
        <h3>Executive Summary</h3>
        <p>This report details the findings of automated testing for Logout Functionality (OTG-SESS-006) on the DVWA application. Proper logout functionality is crucial for session management security, ensuring that user sessions are completely terminated when users intentionally end their session.</p>
        <p><strong>Risk Rating: <span class="risk-rating">{risk_rating}</span></strong></p>
        <p><strong>CVSS Score: <span class="cvss-score">{cvss_score}</span></strong></p>
        <p><strong>Vulnerable Security Levels: {vulnerable_count}/{len([r for r in test_results if not r['error']])}</strong></p>
    </div>

    <h2>Test Details</h2>
    <h3>Methodology</h3>
    <p>The following methodology was used to test logout functionality:</p>
    <ul>
        <li>Logged into DVWA with valid credentials at different security levels</li>
        <li>Performed logout operation and verified session termination</li>
        <li>Tested if session tokens are invalidated server-side</li>
        <li>Verified user redirection to login page after logout</li>
        <li>Tested session reuse with old session IDs</li>
        <li>Checked if cached pages can be accessed after logout</li>
        <li>Analyzed session state before and after logout</li>
    </ul>

    <h3>Test Results</h3>
    {results_html}
    {cache_html}

    <div class="recommendations">
        <h3>Remediation Recommendations</h3>
        <ul>
            <li>Properly invalidate sessions on the server side during logout</li>
            <li>Destroy all session data associated with the user</li>
            <li>Redirect users to the login page after successful logout</li>
            <li>Implement proper session timeout mechanisms</li>
            <li>Prevent session fixation by regenerating session IDs</li>
            <li>Clear client-side session storage and cookies</li>
            <li>Implement logout on all tabs/windows (broadcast logout)</li>
            <li>Use secure headers to prevent caching of sensitive pages</li>
        </ul>
        <h4>Secure Implementation Example:</h4>
        <pre>// PHP example
session_start();
// Destroy all session data
$_SESSION = array();
// Delete session cookie
if (ini_get("session.use_cookies")) {{
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}}
// Destroy session
session_destroy();
// Redirect to login
header("Location: login.php");</pre>
    </div>

    <div class="references">
        <h3>References</h3>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/06-Testing_for_Logout_Functionality" target="_blank">OWASP Testing Guide - OTG-SESS-006</a></li>
            <li><a href="https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet" target="_blank">OWASP Session Management Cheat Sheet</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/613.html" target="_blank">CWE-613: Insufficient Session Expiration</a></li>
            <li><a href="https://owasp.org/www-community/attacks/Session_hijacking_attack" target="_blank">OWASP Session Hijacking</a></li>
        </ul>
    </div>
</body>
</html>"""
    
    return html_content

def check_dvwa_accessibility():
    """Check if DVWA is accessible"""
    try:
        print("[+] Checking DVWA accessibility")
        response = session.get(DVWA_BASE_URL, timeout=15)
        is_accessible = response.status_code == 200 and ("Damn Vulnerable Web App" in response.text or "login" in response.text.lower())
        if is_accessible:
            print("[+] DVWA is accessible")
        else:
            print("[-] DVWA is not accessible")
        return is_accessible
    except Exception as e:
        print(f"[-] Error checking DVWA accessibility: {str(e)}")
        return False

def main():
    """Main execution function"""
    print("[*] Starting Logout Functionality Test (OTG-SESS-006)")
    print(f"[*] Target: {DVWA_BASE_URL}")
    
    # Check if DVWA is accessible
    if not check_dvwa_accessibility():
        print("[-] Exiting due to DVWA inaccessibility")
        return
    
    # Login to DVWA
    if not login():
        print("[-] Exiting due to login failure")
        return
    
    # Test logout functionality at different security levels
    print("[*] Testing logout functionality across security levels...")
    security_levels = ['low', 'medium', 'high']
    test_results = []
    
    for level in security_levels:
        result = test_logout_at_security_level(level)
        test_results.append(result)
    
    # Test cached page access
    print("\n[*] Testing cached page access after logout...")
    cache_test_result = test_cached_page_access()
    
    # Generate HTML report
    print("\n[*] Generating HTML report...")
    html_report = generate_html_report(test_results, cache_test_result)
    
    try:
        with open("OTG-SESS-006_Logout_Functionality_Report.html", "w", encoding="utf-8") as f:
            f.write(html_report)
        print("[+] HTML report saved as 'OTG-SESS-006_Logout_Functionality_Report.html'")
    except Exception as e:
        print(f"[-] Failed to save HTML report: {str(e)}")
    
    # Print summary
    print("\n" + "="*60)
    print("LOGOUT FUNCTIONALITY TEST SUMMARY")
    print("="*60)
    
    vulnerable_count = 0
    
    for result in test_results:
        print(f"\nSecurity Level: {result['security_level'].capitalize()}")
        if result['error']:
            print(f"  Error: {result['error']}")
        elif result['findings']:
            status = "VULNERABLE" if result['findings']['vulnerable'] else "NOT VULNERABLE"
            print(f"  Status: {status}")
            for detail in result['findings']['details']:
                print(f"    {detail}")
            if result['findings']['vulnerable']:
                vulnerable_count += 1
    
    print(f"\nCache Test Result:")
    cache_status = "VULNERABLE" if cache_test_result['can_access_cached'] else "NOT VULNERABLE"
    print(f"  Status: {cache_status}")
    print(f"  Details: {cache_test_result['details']}")
    
    print(f"\nOverall Results: {vulnerable_count}/{len([r for r in test_results if not r['error']])} security levels show vulnerabilities")
    print(f"Report saved to: OTG-SESS-006_Logout_Functionality_Report.html")
    print("="*60)

if __name__ == "__main__":
    main()