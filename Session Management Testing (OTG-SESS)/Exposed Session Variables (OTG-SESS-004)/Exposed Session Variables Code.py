import requests
from bs4 import BeautifulSoup
import datetime
import re
import urllib3
from urllib.parse import urlparse, parse_qs

# Disable SSL warnings if needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
DVWA_BASE_URL = "http://localhost/dvwa/"
LOGIN_URL = "http://localhost/dvwa/login.php"
SECURITY_URL = "http://localhost/dvwa/security.php"
USERNAME = "admin"
PASSWORD = "password"

# Keywords to search for in responses
SESSION_KEYWORDS = [
    'session', 'token', 'PHPSESSID', 'auth', 'login', 'password', 
    'user_token', 'id', 'role', 'level', 'username', 'userid',
    'credential', 'cookie', 'sess'
]

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

def check_url_for_session_data(url):
    """Check if URL contains session data in query parameters"""
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    exposed_params = []
    for param_name, param_values in query_params.items():
        param_name_lower = param_name.lower()
        for keyword in SESSION_KEYWORDS:
            if keyword in param_name_lower:
                exposed_params.append({
                    'parameter': param_name,
                    'value': param_values[0] if param_values else '',
                    'keyword': keyword
                })
    
    return exposed_params

def search_html_for_session_data(html_content, url):
    """Search HTML content for exposed session variables"""
    findings = []
    
    # Parse HTML
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Search in comments
    comments = soup.find_all(string=lambda text: isinstance(text, str) and any(keyword in text.lower() for keyword in SESSION_KEYWORDS))
    for comment in comments:
        for keyword in SESSION_KEYWORDS:
            if keyword in comment.lower():
                findings.append({
                    'type': 'HTML Comment',
                    'location': url,
                    'content': str(comment)[:200] + '...' if len(str(comment)) > 200 else str(comment),
                    'keyword': keyword,
                    'risk': 'Medium'
                })
    
    # Search in meta tags
    meta_tags = soup.find_all('meta')
    for meta in meta_tags:
        attrs_str = ' '.join([f"{k}={v}" for k, v in meta.attrs.items()]).lower()
        for keyword in SESSION_KEYWORDS:
            if keyword in attrs_str:
                findings.append({
                    'type': 'Meta Tag',
                    'location': url,
                    'content': str(meta)[:200] + '...' if len(str(meta)) > 200 else str(meta),
                    'keyword': keyword,
                    'risk': 'Medium'
                })
    
    # Search in hidden form fields
    hidden_inputs = soup.find_all('input', {'type': 'hidden'})
    for hidden_input in hidden_inputs:
        name = hidden_input.get('name', '').lower()
        value = hidden_input.get('value', '')
        for keyword in SESSION_KEYWORDS:
            if keyword in name:
                findings.append({
                    'type': 'Hidden Form Field',
                    'location': url,
                    'content': f"name='{hidden_input.get('name')}' value='{value[:50]}{'...' if len(value) > 50 else ''}'",
                    'keyword': keyword,
                    'risk': 'High' if 'token' in keyword or 'session' in keyword else 'Medium'
                })
    
    # Search in JavaScript variables
    script_tags = soup.find_all('script')
    for script in script_tags:
        if script.string:
            script_content = script.string
            for keyword in SESSION_KEYWORDS:
                if keyword in script_content.lower():
                    # Find lines containing the keyword
                    lines = script_content.split('\n')
                    for i, line in enumerate(lines):
                        if keyword in line.lower() and ('=' in line or 'var' in line or 'let' in line or 'const' in line):
                            findings.append({
                                'type': 'JavaScript Variable',
                                'location': url,
                                'content': line.strip()[:200] + '...' if len(line.strip()) > 200 else line.strip(),
                                'keyword': keyword,
                                'risk': 'High'
                            })
                            break
    
    return findings

def search_response_for_session_data(response_text, url):
    """Search response text for session data patterns"""
    findings = []
    
    # Search for common session patterns
    patterns = [
        (r'[\'"]?(PHPSESSID|JSESSIONID|ASP\.NET_SessionId)[\'"]?\s*[:=]\s*[\'"]([^\'"]+)[\'"]', 'Session ID Assignment'),
        (r'[\'"]?(token|session|auth)[\'"]?\s*[:=]\s*[\'"]([^\'"]{10,})[\'"]', 'Token Assignment'),
        (r'(session|token|auth).*[=:].*[a-zA-Z0-9]{10,}', 'Session Variable Pattern')
    ]
    
    for pattern, description in patterns:
        matches = re.finditer(pattern, response_text, re.IGNORECASE)
        for match in matches:
            findings.append({
                'type': description,
                'location': url,
                'content': match.group(0)[:200] + '...' if len(match.group(0)) > 200 else match.group(0),
                'keyword': match.group(1) if len(match.groups()) > 0 else 'pattern',
                'risk': 'High'
            })
    
    return findings

def test_exposed_session_variables():
    """Test for exposed session variables across multiple pages"""
    all_findings = []
    
    # Pages to test
    test_pages = [
        DVWA_BASE_URL,
        "http://localhost/dvwa/",
        "http://localhost/dvwa/security.php",
        "http://localhost/dvwa/phpinfo.php",
        "http://localhost/dvwa/instructions.php"
    ]
    
    for page_url in test_pages:
        try:
            print(f"[+] Testing {page_url}")
            
            # Check URL for session parameters
            exposed_params = check_url_for_session_data(page_url)
            for param in exposed_params:
                all_findings.append({
                    'type': 'URL Parameter',
                    'location': page_url,
                    'content': f"{param['parameter']}={param['value'][:30]}{'...' if len(param['value']) > 30 else ''}",
                    'keyword': param['keyword'],
                    'risk': 'High'
                })
            
            # Get page content
            response = session.get(page_url, timeout=15)
            
            # Search HTML for session data
            html_findings = search_html_for_session_data(response.text, page_url)
            all_findings.extend(html_findings)
            
            # Search response text for patterns
            pattern_findings = search_response_for_session_data(response.text, page_url)
            all_findings.extend(pattern_findings)
            
        except Exception as e:
            print(f"[-] Error testing {page_url}: {str(e)}")
    
    # Remove duplicates
    unique_findings = []
    seen = set()
    for finding in all_findings:
        key = (finding['type'], finding['location'], finding['content'])
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    return unique_findings

def generate_html_report(findings):
    """Generate OSCP-style HTML report"""
    
    # Calculate risk statistics
    high_risk = sum(1 for f in findings if f['risk'] == 'High')
    medium_risk = sum(1 for f in findings if f['risk'] == 'Medium')
    
    if high_risk > 0:
        risk_rating = "HIGH"
        risk_color = "#ff6b6b"
    elif medium_risk > 0:
        risk_rating = "MEDIUM"
        risk_color = "#ffd93d"
    else:
        risk_rating = "LOW"
        risk_color = "#6bcf7f"
    
    # Generate findings table
    findings_html = ""
    if findings:
        findings_html += """
        <table>
            <tr>
                <th>Type</th>
                <th>Location</th>
                <th>Content</th>
                <th>Keyword</th>
                <th>Risk</th>
            </tr>"""
        
        for finding in findings:
            risk_class = "high-risk" if finding['risk'] == 'High' else "medium-risk" if finding['risk'] == 'Medium' else "low-risk"
            findings_html += f"""
            <tr>
                <td>{finding['type']}</td>
                <td>{finding['location']}</td>
                <td><pre>{finding['content']}</pre></td>
                <td>{finding['keyword']}</td>
                <td class="{risk_class}">{finding['risk']}</td>
            </tr>"""
        
        findings_html += "</table>"
    else:
        findings_html = "<p>No exposed session variables found.</p>"
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Exposed Session Variables Test - OTG-SESS-004</title>
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
        .findings-table {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .risk-rating {{
            display: inline-block;
            padding: 5px 10px;
            font-weight: bold;
            background-color: {risk_color};
            color: #000;
        }}
        .high-risk {{
            color: #ff6b6b;
            font-weight: bold;
        }}
        .medium-risk {{
            color: #ffd93d;
        }}
        .low-risk {{
            color: #6bcf7f;
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
            vertical-align: top;
        }}
        th {{
            background-color: #252526;
            color: #569cd6;
        }}
        pre {{
            background-color: #2d2d30;
            border: 1px solid #3c3c3c;
            padding: 10px;
            margin: 5px 0;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
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
        <h1>OWASP Testing Guide - OTG-SESS-004</h1>
        <h2>Exposed Session Variables Test Report</h2>
        <div class="timestamp">Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        <div>Target: <a href="{DVWA_BASE_URL}" target="_blank">{DVWA_BASE_URL}</a></div>
    </div>

    <div class="summary-box">
        <h3>Executive Summary</h3>
        <p>This report details the findings of automated testing for Exposed Session Variables (OTG-SESS-004) on the DVWA application. The tests focused on identifying session-related information that is unnecessarily exposed to the client-side, which could potentially be exploited by attackers to hijack sessions or gain unauthorized access.</p>
        <p><strong>Risk Rating: <span class="risk-rating">{risk_rating}</span></strong></p>
        <p><strong>Findings: {len(findings)}</strong></p>
    </div>

    <h2>Test Details</h2>
    <h3>Methodology</h3>
    <p>The following methodology was used to test for exposed session variables:</p>
    <ul>
        <li>Logged into DVWA with valid credentials</li>
        <li>Navigated through multiple application pages</li>
        <li>Analyzed HTML source code for session-related variables</li>
        <li>Checked URLs for session data in query parameters</li>
        <li>Scanned JavaScript code for exposed session tokens</li>
        <li>Reviewed HTML comments and meta tags for sensitive data</li>
        <li>Identified hidden form fields containing session information</li>
    </ul>

    <h3>Exposed Session Variables Findings</h3>
    <div class="findings-table">
        {findings_html}
    </div>

    <div class="recommendations">
        <h3>Remediation Recommendations</h3>
        <ul>
            <li>Avoid passing session identifiers in URLs or query parameters</li>
            <li>Do not store session tokens in client-side JavaScript variables</li>
            <li>Remove session-related information from HTML comments and meta tags</li>
            <li>Ensure hidden form fields do not contain sensitive session data</li>
            <li>Implement proper server-side session management</li>
            <li>Use HTTPOnly and Secure flags for session cookies</li>
            <li>Regularly audit application code for exposed sensitive information</li>
            <li>Implement Content Security Policy (CSP) to restrict script execution</li>
        </ul>
        <h4>Secure Implementation Example:</h4>
        <pre>// Instead of:
var sessionToken = "abc123xyz";
// Use server-side session management

// Instead of:
<input type="hidden" name="session_id" value="<?php echo $session_id; ?>">
// Use session cookies or server-side storage</pre>
    </div>

    <div class="references">
        <h3>References</h3>
        <ul>
            <li><a href="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Exposed_Session_Variables" target="_blank">OWASP Testing Guide - OTG-SESS-004</a></li>
            <li><a href="https://owasp.org/www-project-cheat-sheets/cheatsheets/Session_Management_Cheat_Sheet" target="_blank">OWASP Session Management Cheat Sheet</a></li>
            <li><a href="https://cwe.mitre.org/data/definitions/200.html" target="_blank">CWE-200: Exposure of Sensitive Information to an Unauthorized Actor</a></li>
            <li><a href="https://owasp.org/www-community/attacks/Session_hijacking_attack" target="_blank">OWASP Session Hijacking</a></li>
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
    print("[*] Starting Exposed Session Variables Test (OTG-SESS-004)")
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
    
    # Test for exposed session variables
    print("[*] Testing for exposed session variables...")
    findings = test_exposed_session_variables()
    
    # Generate HTML report
    print("[*] Generating HTML report...")
    html_report = generate_html_report(findings)
    
    try:
        with open("OTG-SESS-004_Exposed_Session_Variables_Report.html", "w", encoding="utf-8") as f:
            f.write(html_report)
        print("[+] HTML report saved as 'OTG-SESS-004_Exposed_Session_Variables_Report.html'")
    except Exception as e:
        print(f"[-] Failed to save HTML report: {str(e)}")
    
    # Print summary
    print("\n" + "="*60)
    print("EXPOSED SESSION VARIABLES TEST SUMMARY")
    print("="*60)
    
    high_risk = sum(1 for f in findings if f['risk'] == 'High')
    medium_risk = sum(1 for f in findings if f['risk'] == 'Medium')
    
    print(f"Total Findings: {len(findings)}")
    print(f"High Risk: {high_risk}")
    print(f"Medium Risk: {medium_risk}")
    
    if findings:
        print("\nDetailed Findings:")
        for i, finding in enumerate(findings, 1):
            print(f"  {i}. {finding['type']} ({finding['risk']} risk)")
            print(f"     Location: {finding['location']}")
            print(f"     Keyword: {finding['keyword']}")
    else:
        print("No exposed session variables found.")
    
    print(f"\nReport saved to: OTG-SESS-004_Exposed_Session_Variables_Report.html")
    print("="*60)

if __name__ == "__main__":
    main()