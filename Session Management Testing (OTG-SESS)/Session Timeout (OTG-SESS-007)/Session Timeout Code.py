import requests
from bs4 import BeautifulSoup
import datetime
import time
import urllib3
from urllib.parse import urljoin

# Disable SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
DVWA_BASE_URL = "http://localhost/dvwa/"
LOGIN_URL = "http://localhost/dvwa/login.php"
SECURITY_URL = "http://localhost/dvwa/security.php"
USERNAME = "admin"
PASSWORD = "password"

# Timeout test intervals in seconds (for testing purposes - use shorter intervals)
# In real testing, you might want longer intervals like [60, 300, 600, 900] (1, 5, 10, 15 minutes)
TIMEOUT_INTERVALS = [30, 60, 120]  # 30 seconds, 1 minute, 2 minutes for testing

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

def test_session_timeout(interval_seconds):
    """Test session timeout for a specific interval"""
    test_result = {
        'interval': interval_seconds,
        'start_time': None,
        'end_time': None,
        'session_id_before': None,
        'session_id_after': None,
        'authenticated_before': False,
        'authenticated_after': False,
        'session_expired': False,
        'redirects_to_login': False,
        'elapsed_time': 0,
        'details': []
    }
    
    try:
        print(f"[+] Testing session timeout for {interval_seconds} seconds")
        
        # Record initial state
        test_result['start_time'] = datetime.datetime.now()
        test_result['session_id_before'] = get_session_id()
        test_result['authenticated_before'] = is_authenticated()
        
        print(f"[+] Session ID before wait: {test_result['session_id_before']}")
        print(f"[+] Authenticated before wait: {test_result['authenticated_before']}")
        
        if not test_result['authenticated_before']:
            test_result['details'].append("ERROR: Not authenticated before timeout test")
            print("[-] Not authenticated before timeout test")
            return test_result
        
        # Wait for specified interval
        print(f"[+] Waiting for {interval_seconds} seconds...")
        time.sleep(interval_seconds)
        
        # Record end time
        test_result['end_time'] = datetime.datetime.now()
        test_result['elapsed_time'] = (test_result['end_time'] - test_result['start_time']).total_seconds()
        
        # Check session state after wait
        test_result['session_id_after'] = get_session_id()
        test_result['authenticated_after'] = is_authenticated()
        
        print(f"[+] Session ID after wait: {test_result['session_id_after']}")
        print(f"[+] Authenticated after wait: {test_result['authenticated_after']}")
        
        # Determine if session expired
        if not test_result['authenticated_after']:
            test_result['session_expired'] = True
            test_result['details'].append(f"Session expired after {interval_seconds} seconds")
            print(f"[+] Session expired after {interval_seconds} seconds")
            
            # Check if redirected to login page
            try:
                response = session.get(DVWA_BASE_URL, timeout=15)
                if "login" in response.url.lower() or "login" in response.text.lower():
                    test_result['redirects_to_login'] = True
                    test_result['details'].append("User redirected to login page after session expiration")
                    print("[+] User redirected to login page after session expiration")
                else:
                    test_result['details'].append("User NOT redirected to login page after session expiration")
                    print("[-] User NOT redirected to login page after session expiration")
            except Exception as e:
                test_result['details'].append(f"Error checking redirection: {str(e)}")
                print(f"[-] Error checking redirection: {str(e)}")
        else:
            test_result['details'].append(f"Session still active after {interval_seconds} seconds")
            print(f"[-] Session still active after {interval_seconds} seconds")
            
    except Exception as e:
        error_msg = f"ERROR during timeout test: {str(e)}"
        test_result['details'].append(error_msg)
        print(f"[-] {error_msg}")
    
    return test_result

def test_session_timeout_at_security_level(level):
    """Test session timeout functionality at specific security level"""
    result = {
        'security_level': level,
        'test_results': [],
        'error': None
    }
    
    try:
        print(f"\n[+] Testing session timeout at {level} security level")
        
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
        
        # Test each timeout interval
        for interval in TIMEOUT_INTERVALS:
            test_result = test_session_timeout(interval)
            result['test_results'].append(test_result)
            
    except Exception as e:
        result['error'] = f"Error testing {level} security level: {str(e)}"
        print(f"[-] {result['error']}")
    
    return result

def test_session_reuse_after_timeout():
    """Test if expired sessions can be reused"""
    findings = {
        'can_reuse_expired': False,
        'details': ''
    }
    
    try:
        print("[+] Testing session reuse after timeout")
        
        # Login
        if not login():
            findings['details'] = "Failed to login for session reuse test"
            print("[-] Failed to login for session reuse test")
            return findings
        
        # Get session ID
        session_id = get_session_id()
        if not session_id:
            findings['details'] = "Failed to get session ID"
            print("[-] Failed to get session ID")
            return findings
        
        print(f"[+] Current session ID: {session_id}")
        
        # Wait for a short timeout period
        wait_time = 60  # 1 minute
        print(f"[+] Waiting for {wait_time} seconds to simulate timeout...")
        time.sleep(wait_time)
        
        # Check if session is still valid
        if not is_authenticated():
            print("[+] Session appears to have expired naturally")
            
            # Try to reuse the old session
            print("[+] Testing reuse of potentially expired session")
            reuse_session = requests.Session()
            reuse_session.verify = False
            reuse_session.cookies.set('PHPSESSID', session_id)
            
            try:
                reuse_response = reuse_session.get(DVWA_BASE_URL, timeout=15)
                success_indicators = [
                    "Welcome :: Damn Vulnerable Web Application",
                    "dvwa_logo.png",
                    "Security Level",
                    "Logout"
                ]
                session_reused = any(indicator in reuse_response.text for indicator in success_indicators)
                
                if session_reused:
                    findings['can_reuse_expired'] = True
                    findings['details'] = f"Can reuse expired session ID: {session_id}"
                    print(f"[!] VULNERABLE: Can reuse expired session ID: {session_id}")
                else:
                    findings['details'] = "Cannot reuse expired session ID"
                    print("[+] NOT VULNERABLE: Cannot reuse expired session ID")
            except Exception as e:
                findings['details'] = f"Error testing session reuse: {str(e)}"
                print(f"[-] Error testing session reuse: {str(e)}")
        else:
            findings['details'] = "Session did not expire during test period"
            print("[-] Session did not expire during test period")
            
    except Exception as e:
        error_msg = f"Error in session reuse test: {str(e)}"
        findings['details'] = error_msg
        print(f"[-] {error_msg}")
    
    return findings

def generate_html_report(test_results, reuse_test_result):
    """Generate OSCP-style HTML report"""
    
    # Calculate overall risk
    expired_sessions = 0
    total_intervals = 0
    long_sessions = 0  # Sessions that lasted longer than recommended
    
    for result in test_results:
        if not result['error']:
            for test_result in result['test_results']:
                total_intervals += 1
                if test_result['session_expired']:
                    expired_sessions += 1
                # Check if session lasted longer than recommended (e.g., 10 minutes = 600 seconds)
                if not test_result['session_expired'] and test_result['interval'] >= 600:
                    long_sessions += 1
    
    # Risk assessment
    if long_sessions > 0:
        risk_rating = "HIGH"
        risk_color = "#ff6b6b"
        cvss_score = "7.4 (High)"
    elif expired_sessions < total_intervals * 0.5:  # Less than 50% of sessions expired
        risk_rating = "MEDIUM"
        risk_color = "#ffd93d"
        cvss_score = "4.3 (Medium)"
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
        else:
            for test_result in result['test_results']:
                status_class = "fail" if not test_result['session_expired'] else "pass"
                status_text = "ACTIVE" if not test_result['session_expired'] else "EXPIRED"
                
                results_html += f"""
            <div class="finding">
                <p><strong>Test Interval:</strong> {test_result['interval']} seconds</p>
                <p><strong>Status:</strong> <span class="{status_class}">{status_text}</span></p>
                <p><strong>Session ID Before:</strong> {test_result['session_id_before'] or 'None'}</p>
                <p><strong>Session ID After:</strong> {test_result['session_id_after'] or 'None'}</p>
                <p><strong>Authenticated Before:</strong> {test_result['authenticated_before']}</p>
                <p><strong>Authenticated After:</strong> {test_result['authenticated_after']}</p>
                <p><strong>Redirects to Login:</strong> {test_result['redirects_to_login']}</p>
                <p><strong>Elapsed Time:</strong> {test_result['elapsed_time']:.2f} seconds</p>
                <div class="details">
                    <strong>Details:</strong>
                    <ul>"""
                
                for detail in test_result['details']:
                    results_html += f"<li>{detail}</li>"
                
                results_html += """
                    </ul>
                </div>
            </div>"""
        
        results_html += "</div>"
    
    # Add session reuse test results
    reuse_status_class = "fail" if reuse_test_result['can_reuse_expired'] else "pass"
    reuse_status_text = "VULNERABLE" if reuse_test_result['can_reuse_expired'] else "NOT VULNERABLE"
    
    reuse_html = f"""
        <div class="reuse-test">
            <h3>Session Reuse After Timeout Test</h3>
            <div class="finding">
                <p><strong>Status:</strong> <span class="{reuse_status_class}">{reuse_status_text}</span></p>
                <p><strong>Details:</strong> {reuse_test_result['details']}</p>
            </div>
        </div>"""
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Session Timeout Test - OTG-SESS-007</title>
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
        .security-level, .reuse-test {{
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
        <h1>OWASP Testing Guide - OTG-SESS-007</h1>
        <h2>Session Timeout Test Report</h2>
        <div class="timestamp">Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div>Target: <a href="{DVWA_BASE_URL}" target="_blank">{DVWA_BASE_URL}</a></div>
    </div>

    <div class="summary-box">
        <h3>Executive Summary</h3>
        <p>This report details the findings of automated testing for Session Timeout (OTG-SESS-007) on the DVWA application. Session timeout is a critical security control that helps protect against unauthorized access by automatically terminating user sessions after a period of inactivity.</p>
        <p><strong>Risk Rating: <span class="risk-rating">{risk_rating}</span></strong></p>
        <p><strong>CVSS Score: <span class="cvss-score">{cvss_score}</span></strong></p>
        <p><strong>Sessions Expired: {expired_sessions}/{total_intervals} test intervals</strong></p>
    </div>

    <h2>Test Details</h2>
    <h3>Methodology</h3>
    <p>The following methodology was used to test session timeout functionality:</p>
    <ul>
        <li>Logged into DVWA with valid credentials at different security levels</li>
        <li>Waited for specified timeout intervals (30 seconds, 1 minute, 2 minutes)</li>
        <li>Attempted to access protected resources after each interval</li>
        <li>Verified session expiration and proper invalidation</li>
        <li>Tested user redirection to login page after timeout</li>
        <li>Evaluated session reuse with expired session IDs</li>
        <li>Analyzed session state before and after timeout periods</li>
    </ul>

    <h3>Test Results</h3>
    {results_html}
    {reuse_html}

    <div class="recommendations">
        <h3>Remediation Recommendations</h3>
        <ul>
            <li>Implement appropriate session timeout periods (5-30 minutes for web applications)</li>
            <li>Properly invalidate sessions on the server side when they expire</li>
            <li>Redirect users to the login page after session timeout</li>
            <li>Destroy all session data associated with expired sessions</li>
            <li>Prevent reuse of expired session tokens</li>
            <li>Implement sliding timeout mechanisms for better user experience</li>
            <li>Consider different timeout values for different user roles</li>
            <li>Log session timeout events for security monitoring</li>
        </ul>
        <h4>Recommended Timeout Values:</h4>
        <ul>
            <li><strong>High Security:</strong> 5-15 minutes of inactivity</li>
            <li><strong>Standard Security:</strong> 15-30 minutes of inactivity</li>
            <li><strong>Low Security:</strong> 30-60 minutes of inactivity</li>
        </ul>
        <h4>Secure Implementation Example:</h4>
        <pre>// PHP example
session_start();
$timeout_duration = 1800; // 30 minutes

// Check if session has expired
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $timeout_duration)) {{
    // Session has expired
    session_unset();
    session_destroy();
    header("Location: login.php");
    exit();
}}

// Update last activity time
$_SESSION['last_activity'] = time();</pre>
    </div>

    <div class="references">
        <h3>References</h3>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_for_Session_Timeout" target="_blank">OWASP Testing Guide - OTG-SESS-007</a></li>
            <li><a href="https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet" target="_blank">OWASP Session Management Cheat Sheet</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/613.html" target="_blank">CWE-613: Insufficient Session Expiration</a></li>
            <li><a href="https://owasp.org/www-community/controls/Session_Timeout" target="_blank">OWASP Session Timeout</a></li>
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
    print("[*] Starting Session Timeout Test (OTG-SESS-007)")
    print(f"[*] Target: {DVWA_BASE_URL}")
    print(f"[*] Testing intervals: {TIMEOUT_INTERVALS} seconds")
    
    # Check if DVWA is accessible
    if not check_dvwa_accessibility():
        print("[-] Exiting due to DVWA inaccessibility")
        return
    
    # Login to DVWA
    if not login():
        print("[-] Exiting due to login failure")
        return
    
    # Test session timeout functionality at different security levels
    print("[*] Testing session timeout across security levels...")
    security_levels = ['low', 'medium', 'high']
    test_results = []
    
    for level in security_levels:
        result = test_session_timeout_at_security_level(level)
        test_results.append(result)
    
    # Test session reuse after timeout
    print("\n[*] Testing session reuse after timeout...")
    reuse_test_result = test_session_reuse_after_timeout()
    
    # Generate HTML report
    print("\n[*] Generating HTML report...")
    html_report = generate_html_report(test_results, reuse_test_result)
    
    try:
        with open("OTG-SESS-007_Session_Timeout_Report.html", "w", encoding="utf-8") as f:
            f.write(html_report)
        print("[+] HTML report saved as 'OTG-SESS-007_Session_Timeout_Report.html'")
    except Exception as e:
        print(f"[-] Failed to save HTML report: {str(e)}")
    
    # Print summary
    print("\n" + "="*60)
    print("SESSION TIMEOUT TEST SUMMARY")
    print("="*60)
    
    expired_sessions = 0
    total_intervals = 0
    
    for result in test_results:
        print(f"\nSecurity Level: {result['security_level'].capitalize()}")
        if result['error']:
            print(f"  Error: {result['error']}")
        else:
            for test_result in result['test_results']:
                total_intervals += 1
                status = "EXPIRED" if test_result['session_expired'] else "ACTIVE"
                print(f"  {test_result['interval']} seconds: {status}")
                for detail in test_result['details']:
                    print(f"    {detail}")
                if test_result['session_expired']:
                    expired_sessions += 1
    
    print(f"\nSession Reuse Test:")
    reuse_status = "VULNERABLE" if reuse_test_result['can_reuse_expired'] else "NOT VULNERABLE"
    print(f"  Status: {reuse_status}")
    print(f"  Details: {reuse_test_result['details']}")
    
    print(f"\nOverall Results: {expired_sessions}/{total_intervals} sessions expired during testing")
    print(f"Report saved to: OTG-SESS-007_Session_Timeout_Report.html")
    print("="*60)

if __name__ == "__main__":
    main()