import requests
from bs4 import BeautifulSoup
import datetime
import urllib3
from urllib.parse import urljoin

# Disable SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
DVWA_BASE_URL = "http://localhost/dvwa/"
LOGIN_URL = "http://localhost/dvwa/login.php"
SECURITY_URL = "http://localhost/dvwa/security.php"
CHANGE_PWD_URL = "http://localhost/dvwa/vulnerabilities/csrf/"
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

def get_current_security_level():
    """Get current DVWA security level"""
    try:
        response = session.get(SECURITY_URL, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for selected security level
        security_select = soup.find('select', {'name': 'security'})
        if security_select:
            selected_option = security_select.find('option', {'selected': True})
            if selected_option:
                return selected_option.get('value', 'unknown')
        return 'unknown'
    except Exception:
        return 'unknown'

def test_csrf_protection(url, form_data=None):
    """Test CSRF protection for a given URL and form"""
    findings = {
        'url': url,
        'has_csrf_protection': False,
        'vulnerable': False,
        'details': '',
        'test_results': []
    }
    
    try:
        # Get the original form to analyze CSRF tokens
        response = session.get(url, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find forms
        forms = soup.find_all('form')
        if not forms:
            findings['details'] = "No forms found on page"
            return findings
        
        # Analyze each form
        for i, form in enumerate(forms):
            # Look for CSRF tokens in the form
            csrf_tokens = form.find_all('input', {'name': lambda x: x and 'token' in x.lower()})
            if not csrf_tokens:
                csrf_tokens = form.find_all('input', {'id': lambda x: x and 'token' in x.lower()})
            
            if csrf_tokens:
                findings['has_csrf_protection'] = True
                findings['test_results'].append(f"Form {i+1}: CSRF token found ({csrf_tokens[0].get('name', 'unknown')})")
            else:
                findings['test_results'].append(f"Form {i+1}: No CSRF token found")
        
        # If no CSRF protection found, test if we can submit without tokens
        if not findings['has_csrf_protection'] and form_data:
            # Try submitting without CSRF token
            try:
                submit_response = session.post(url, data=form_data, timeout=15)
                
                # Check if the action was successful
                if "success" in submit_response.text.lower() or "updated" in submit_response.text.lower():
                    findings['vulnerable'] = True
                    findings['details'] = "Form can be submitted without CSRF token"
                else:
                    findings['details'] = "Form requires authentication or has other protections"
            except Exception as e:
                findings['details'] = f"Error testing form submission: {str(e)}"
        
        if not form_data:
            findings['details'] = "No form data provided for testing"
            
    except Exception as e:
        findings['details'] = f"Error analyzing CSRF protection: {str(e)}"
    
    return findings

def test_security_level_change():
    """Test CSRF protection on security level change form"""
    findings = {
        'test_name': 'Security Level Change CSRF Test',
        'vulnerable': False,
        'details': '',
        'request_samples': []
    }
    
    try:
        # Get current security level
        current_level = get_current_security_level()
        target_level = 'medium' if current_level != 'medium' else 'low'
        
        # Get CSRF token for security form
        csrf_token = get_csrf_token(SECURITY_URL)
        if not csrf_token:
            findings['details'] = "Failed to get CSRF token for security form"
            return findings
        
        # Test 1: Valid request (should work)
        valid_data = {
            'security': target_level,
            'seclev_submit': 'Submit',
            'user_token': csrf_token
        }
        
        valid_response = session.post(SECURITY_URL, data=valid_data, timeout=15)
        findings['request_samples'].append({
            'description': 'Valid request with CSRF token',
            'data': f"security={target_level}&seclev_submit=Submit&user_token={csrf_token[:10]}...",
            'status': 'Should succeed'
        })
        
        # Test 2: Request without CSRF token
        invalid_data = {
            'security': current_level,
            'seclev_submit': 'Submit'
        }
        
        try:
            invalid_response = session.post(SECURITY_URL, data=invalid_data, timeout=15)
            
            # Check if the request succeeded without token (indicates vulnerability)
            if target_level in invalid_response.text:
                findings['vulnerable'] = True
                findings['details'] = "Security level can be changed without CSRF token"
            else:
                findings['details'] = "Security level change properly protected by CSRF token"
                
        except Exception as e:
            findings['details'] = f"Error testing CSRF protection: {str(e)}"
            
        # Reset to original level
        reset_token = get_csrf_token(SECURITY_URL)
        if reset_token:
            reset_data = {
                'security': current_level,
                'seclev_submit': 'Submit',
                'user_token': reset_token
            }
            session.post(SECURITY_URL, data=reset_data, timeout=15)
            
    except Exception as e:
        findings['details'] = f"Error in security level CSRF test: {str(e)}"
    
    return findings

def test_password_change_csrf():
    """Test CSRF protection on password change form (DVWA CSRF vulnerability page)"""
    findings = {
        'test_name': 'Password Change CSRF Test',
        'vulnerable': False,
        'details': '',
        'request_samples': []
    }
    
    try:
        # Navigate to CSRF vulnerability page
        csrf_page = session.get("http://localhost/dvwa/vulnerabilities/csrf/", timeout=15)
        
        # Extract current password change form
        soup = BeautifulSoup(csrf_page.text, 'html.parser')
        password_form = soup.find('form', {'method': 'GET'})
        
        if password_form:
            # Check if form has CSRF protection
            csrf_inputs = password_form.find_all('input', {'name': lambda x: x and 'token' in x.lower()})
            if not csrf_inputs:
                findings['details'] = "Password change form lacks CSRF protection"
                findings['vulnerable'] = True
            else:
                findings['details'] = "Password change form has CSRF token"
        else:
            findings['details'] = "Password change form not found"
            
    except Exception as e:
        findings['details'] = f"Error testing password change CSRF: {str(e)}"
    
    return findings

def test_all_security_levels():
    """Test CSRF protection at different security levels"""
    results = []
    
    security_levels = ['low', 'medium', 'high']
    
    for level in security_levels:
        print(f"[+] Testing CSRF protection at {level} security level")
        
        # Set security level
        if not set_security_level(level):
            results.append({
                'level': level,
                'status': 'Failed to set',
                'findings': []
            })
            continue
        
        # Test security level change CSRF
        security_test = test_security_level_change()
        
        # Test password change CSRF
        password_test = test_password_change_csrf()
        
        results.append({
            'level': level,
            'status': 'Tested',
            'findings': [security_test, password_test]
        })
    
    return results

def generate_html_report(test_results):
    """Generate OSCP-style HTML report"""
    
    # Calculate overall risk
    vulnerable_count = 0
    total_tests = 0
    
    for level_result in test_results:
        for finding in level_result['findings']:
            total_tests += 1
            if finding['vulnerable']:
                vulnerable_count += 1
    
    if vulnerable_count > 0:
        risk_rating = "HIGH"
        risk_color = "#ff6b6b"
        cvss_score = "8.1 (High)"
    else:
        risk_rating = "LOW"
        risk_color = "#6bcf7f"
        cvss_score = "2.0 (Low)"
    
    # Generate test results HTML
    results_html = ""
    
    for level_result in test_results:
        results_html += f"""
        <div class="security-level">
            <h3>Security Level: {level_result['level'].capitalize()} ({level_result['status']})</h3>"""
        
        for finding in level_result['findings']:
            status_class = "fail" if finding['vulnerable'] else "pass"
            status_text = "VULNERABLE" if finding['vulnerable'] else "NOT VULNERABLE"
            
            results_html += f"""
            <div class="finding">
                <h4>{finding['test_name']}</h4>
                <p><strong>Status:</strong> <span class="{status_class}">{status_text}</span></p>
                <p><strong>Details:</strong> {finding['details']}</p>"""
            
            if 'request_samples' in finding and finding['request_samples']:
                results_html += "<p><strong>Request Samples:</strong></p><ul>"
                for sample in finding['request_samples']:
                    results_html += f"<li>{sample['description']}: {sample['data']}</li>"
                results_html += "</ul>"
            
            results_html += "</div>"
        
        results_html += "</div>"
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF Test - OTG-SESS-005</title>
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
        .security-level {{
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
        ul {{
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
        <h1>OWASP Testing Guide - OTG-SESS-005</h1>
        <h2>CSRF (Cross-Site Request Forgery) Test Report</h2>
        <div class="timestamp">Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div>Target: <a href="{DVWA_BASE_URL}" target="_blank">{DVWA_BASE_URL}</a></div>
    </div>

    <div class="summary-box">
        <h3>Executive Summary</h3>
        <p>This report details the findings of automated testing for Cross-Site Request Forgery (CSRF) vulnerabilities (OTG-SESS-005) on the DVWA application. CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated. CSRF attacks specifically target state-changing requests, not theft of data.</p>
        <p><strong>Risk Rating: <span class="risk-rating">{risk_rating}</span></strong></p>
        <p><strong>CVSS Score: <span class="cvss-score">{cvss_score}</span></strong></p>
        <p><strong>Vulnerable Endpoints: {vulnerable_count}/{total_tests}</strong></p>
    </div>

    <h2>Test Details</h2>
    <h3>Methodology</h3>
    <p>The following methodology was used to test for CSRF vulnerabilities:</p>
    <ul>
        <li>Logged into DVWA with valid credentials</li>
        <li>Tested CSRF protection at different security levels (Low, Medium, High)</li>
        <li>Analyzed forms for the presence of anti-CSRF tokens</li>
        <li>Attempted to submit forms without valid CSRF tokens</li>
        <li>Tested state-changing operations (security level change, password change)</li>
        <li>Verified server-side validation of CSRF tokens</li>
    </ul>

    <h3>Test Results</h3>
    {results_html}

    <div class="recommendations">
        <h3>Remediation Recommendations</h3>
        <ul>
            <li>Implement unique, unpredictable CSRF tokens for all state-changing forms</li>
            <li>Validate CSRF tokens on the server side for every request</li>
            <li>Regenerate CSRF tokens after successful form submission</li>
            <li>Use the SameSite cookie attribute to prevent CSRF attacks</li>
            <li>Consider implementing double submit cookies pattern as additional protection</li>
            <li>Set appropriate security headers (X-Frame-Options, Content-Security-Policy)</li>
            <li>Perform regular security code reviews to identify CSRF vulnerabilities</li>
        </ul>
        <h4>Secure Implementation Example:</h4>
        <pre><form method="POST" action="/change-password">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    <input type="password" name="new_password">
    <input type="submit" value="Change Password">
</form></pre>
    </div>

    <div class="references">
        <h3>References</h3>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery" target="_blank">OWASP Testing Guide - OTG-SESS-005</a></li>
            <li><a href="https://owasp.org/www-community/attacks/csrf" target="_blank">OWASP CSRF Attack</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/352.html" target="_blank">CWE-352: Cross-Site Request Forgery (CSRF)</a></li>
            <li><a href="https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet" target="_blank">OWASP CSRF Prevention Cheat Sheet</a></li>
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
    print("[*] Starting CSRF Test (OTG-SESS-005)")
    print(f"[*] Target: {DVWA_BASE_URL}")
    
    # Check if DVWA is accessible
    if not check_dvwa_accessibility():
        print("[-] Exiting due to DVWA inaccessibility")
        return
    
    # Login to DVWA
    if not login():
        print("[-] Exiting due to login failure")
        return
    
    # Test CSRF protection at different security levels
    print("[*] Testing CSRF protection across security levels...")
    test_results = test_all_security_levels()
    
    # Generate HTML report
    print("[*] Generating HTML report...")
    html_report = generate_html_report(test_results)
    
    try:
        with open("OTG-SESS-005_CSRF_Report.html", "w", encoding="utf-8") as f:
            f.write(html_report)
        print("[+] HTML report saved as 'OTG-SESS-005_CSRF_Report.html'")
    except Exception as e:
        print(f"[-] Failed to save HTML report: {str(e)}")
    
    # Print summary
    print("\n" + "="*60)
    print("CSRF TEST SUMMARY")
    print("="*60)
    
    vulnerable_count = 0
    total_tests = 0
    
    for level_result in test_results:
        print(f"\nSecurity Level: {level_result['level'].capitalize()}")
        for finding in level_result['findings']:
            total_tests += 1
            status = "VULNERABLE" if finding['vulnerable'] else "NOT VULNERABLE"
            print(f"  {finding['test_name']}: {status}")
            print(f"    Details: {finding['details']}")
            if finding['vulnerable']:
                vulnerable_count += 1
    
    print(f"\nOverall Results: {vulnerable_count}/{total_tests} tests indicate vulnerability")
    print(f"Report saved to: OTG-SESS-005_CSRF_Report.html")
    print("="*60)

if __name__ == "__main__":
    main()