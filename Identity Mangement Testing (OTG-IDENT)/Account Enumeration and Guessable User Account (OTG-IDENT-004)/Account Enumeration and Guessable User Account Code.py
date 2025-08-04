import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import re

def get_csrf_token(session, url):
    """Extract CSRF token from DVWA login page"""
    try:
        response = session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        if token_input:
            return token_input['value']
        return None
    except Exception as e:
        print(f"Error getting CSRF token: {e}")
        return None

def test_login_response(session, base_url, username, password):
    """Test login and return response characteristics"""
    try:
        login_url = f"{base_url}/login.php"
        token = get_csrf_token(session, login_url)
        
        if not token:
            return None, "Failed to get CSRF token"
        
        login_data = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': token
        }
        
        # Measure response time and get response content
        start_time = time.time()
        response = session.post(login_url, data=login_data, allow_redirects=False)
        response_time = time.time() - start_time
        
        return {
            'status_code': response.status_code,
            'location': response.headers.get('Location', ''),
            'content': response.text,
            'response_time': response_time,
            'content_length': len(response.text),
            'title': extract_title(response.text)
        }, None
        
    except Exception as e:
        return None, str(e)

def extract_title(html_content):
    """Extract title from HTML content"""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        title_tag = soup.find('title')
        return title_tag.get_text().strip() if title_tag else ""
    except:
        return ""

def test_valid_user_valid_password(session, base_url):
    """Test valid user with valid password"""
    print("[*] Testing valid user with valid password...")
    
    # Test with known valid credentials
    response_data, error = test_login_response(session, base_url, 'admin', 'password')
    
    if error:
        return None, f"Error: {error}"
    
    if not response_data:
        return None, "No response data received"
    
    # Re-login for subsequent tests
    try:
        session.get(f"{base_url}/logout.php")  # Logout first
    except:
        pass
    time.sleep(1)
    
    return response_data, None

def test_valid_user_wrong_password(session, base_url):
    """Test valid user with wrong password"""
    print("[*] Testing valid user with wrong password...")
    
    response_data, error = test_login_response(session, base_url, 'admin', 'wrongpassword123')
    
    if error:
        return None, f"Error: {error}"
    
    if not response_data:
        return None, "No response data received"
    
    return response_data, None

def test_invalid_user_invalid_password(session, base_url):
    """Test invalid user with invalid password"""
    print("[*] Testing invalid user with invalid password...")
    
    response_data, error = test_login_response(session, base_url, 'nonexistentuser123', 'wrongpassword123')
    
    if error:
        return None, f"Error: {error}"
    
    if not response_data:
        return None, "No response data received"
    
    return response_data, None

def analyze_response_differences(valid_good, valid_bad, invalid_bad):
    """Analyze differences between responses to detect enumeration"""
    findings = []
    analysis_details = []
    
    if not all([valid_good, valid_bad, invalid_bad]):
        return findings, analysis_details
    
    # Compare status codes
    codes = {
        'valid_good': valid_good['status_code'],
        'valid_bad': valid_bad['status_code'],
        'invalid_bad': invalid_bad['status_code']
    }
    
    analysis_details.append(f"Status Codes - Valid+Good: {codes['valid_good']}, Valid+Bad: {codes['valid_bad']}, Invalid+Bad: {codes['invalid_bad']}")
    
    if len(set(codes.values())) > 1:
        findings.append({
            'vulnerability': 'Status Code Based Account Enumeration',
            'username': 'Multiple',
            'evidence': f"Different status codes: Valid+Good={codes['valid_good']}, Valid+Bad={codes['valid_bad']}, Invalid+Bad={codes['invalid_bad']}",
            'severity': 'High'
        })
    
    # Compare content lengths
    lengths = {
        'valid_good': valid_good['content_length'],
        'valid_bad': valid_bad['content_length'],
        'invalid_bad': invalid_bad['content_length']
    }
    
    analysis_details.append(f"Content Lengths - Valid+Good: {lengths['valid_good']}, Valid+Bad: {lengths['valid_bad']}, Invalid+Bad: {lengths['invalid_bad']}")
    
    # Check for significant differences (more than 50 bytes)
    length_diff = max(lengths.values()) - min(lengths.values())
    if length_diff > 50:
        findings.append({
            'vulnerability': 'Content Length Based Account Enumeration',
            'username': 'Multiple',
            'evidence': f"Significant length difference: Valid+Bad={lengths['valid_bad']} bytes, Invalid+Bad={lengths['invalid_bad']} bytes (diff: {length_diff} bytes)",
            'severity': 'High'
        })
    
    # Compare response times
    times = {
        'valid_good': valid_good['response_time'],
        'valid_bad': valid_bad['response_time'],
        'invalid_bad': invalid_bad['response_time']
    }
    
    analysis_details.append(f"Response Times - Valid+Good: {times['valid_good']:.3f}s, Valid+Bad: {times['valid_bad']:.3f}s, Invalid+Bad: {times['invalid_bad']:.3f}s")
    
    # Check for timing differences (more than 0.3 seconds)
    time_diff = abs(times['valid_bad'] - times['invalid_bad'])
    if time_diff > 0.3:
        findings.append({
            'vulnerability': 'Timing Based Account Enumeration',
            'username': 'Multiple',
            'evidence': f"Timing difference: Valid+Bad={times['valid_bad']:.3f}s, Invalid+Bad={times['invalid_bad']:.3f}s (diff: {time_diff:.3f}s)",
            'severity': 'Medium'
        })
    
    # Compare titles
    titles = {
        'valid_good': valid_good['title'],
        'valid_bad': valid_bad['title'],
        'invalid_bad': invalid_bad['title']
    }
    
    analysis_details.append(f"Page Titles - Valid+Good: '{titles['valid_good']}', Valid+Bad: '{titles['valid_bad']}', Invalid+Bad: '{titles['invalid_bad']}'")
    
    if titles['valid_bad'] != titles['invalid_bad']:
        findings.append({
            'vulnerability': 'Title Based Account Enumeration',
            'username': 'Multiple',
            'evidence': f"Different titles: Valid+Bad='{titles['valid_bad']}', Invalid+Bad='{titles['invalid_bad']}'",
            'severity': 'High'
        })
    
    # Analyze content for specific error messages
    valid_bad_content = valid_bad['content'].lower()
    invalid_bad_content = invalid_bad['content'].lower()
    
    # Look for user-specific error messages
    user_exists_indicators = [
        'invalid password', 'wrong password', 'incorrect password',
        'password is not correct', 'password incorrect'
    ]
    
    user_not_exists_indicators = [
        'user not found', 'invalid username', 'username not found',
        'no such user', 'unknown user'
    ]
    
    # Check if valid+bad response indicates user exists
    found_user_exists_indicator = False
    for indicator in user_exists_indicators:
        if indicator in valid_bad_content:
            analysis_details.append(f"User Exists Indicator Found: '{indicator}' in valid user + wrong password response")
            found_user_exists_indicator = True
            if indicator not in invalid_bad_content:
                findings.append({
                    'vulnerability': 'Error Message Disclosure - User Existence Confirmed',
                    'username': 'admin',
                    'evidence': f"Response contains '{indicator}' for valid user with wrong password, but not for invalid user",
                    'severity': 'High'
                })
            break
    
    if not found_user_exists_indicator:
        analysis_details.append("No user existence indicators found in valid user + wrong password response")
    
    # Check if invalid+bad response indicates user doesn't exist
    found_user_not_exists_indicator = False
    for indicator in user_not_exists_indicators:
        if indicator in invalid_bad_content:
            analysis_details.append(f"User Not Exists Indicator Found: '{indicator}' in invalid user + wrong password response")
            found_user_not_exists_indicator = True
            if indicator not in valid_bad_content:
                findings.append({
                    'vulnerability': 'Error Message Disclosure - User Non-Existence Revealed',
                    'username': 'nonexistentuser123',
                    'evidence': f"Response contains '{indicator}' for invalid user, but not for valid user",
                    'severity': 'High'
                })
            break
    
    if not found_user_not_exists_indicator:
        analysis_details.append("No user non-existence indicators found in invalid user + wrong password response")
    
    return findings, analysis_details

def test_uri_probing(session, base_url):
    """Test URI probing for user enumeration"""
    findings = []
    
    # Test common user-related paths in DVWA
    user_paths = [
        'admin/',
        'gordonb/',
        'pablo/',
        'smithy/',
        'user/',
        'users/',
        'account/',
        'profile/'
    ]
    
    for path in user_paths:
        try:
            url = f"{base_url}/{path}"
            response = session.get(url, timeout=5)
            
            # Check for different HTTP status codes that might indicate user existence
            if response.status_code == 403:
                findings.append({
                    'vulnerability': 'URI Probing - 403 Forbidden Indicates Possible User',
                    'username': path.rstrip('/'),
                    'evidence': f"Path {path} returned 403 Forbidden - may indicate existing user directory",
                    'severity': 'Medium'
                })
            elif response.status_code == 200 and len(response.text) > 1000:
                findings.append({
                    'vulnerability': 'URI Probing - Content Indicates Possible User',
                    'username': path.rstrip('/'),
                    'evidence': f"Path {path} returned 200 OK with substantial content ({len(response.text)} bytes)",
                    'severity': 'Low'
                })
                
        except Exception as e:
            # 404 errors are expected and normal
            pass
    
    return findings

def test_recovery_facility(session, base_url):
    """Test recovery facility for user enumeration (if available)"""
    findings = []
    
    # Check if DVWA has any password recovery functionality
    try:
        response = session.get(f"{base_url}/")
        if 'forgot' in response.text.lower() or 'recover' in response.text.lower() or 'reset' in response.text.lower():
            findings.append({
                'vulnerability': 'Potential Recovery Facility Enumeration',
                'username': 'N/A',
                'evidence': f"Password recovery/reset functionality detected - may be vulnerable to user enumeration",
                'severity': 'Medium'
            })
    except Exception as e:
        pass
    
    return findings

def test_empty_password(session, base_url):
    """Test valid users with empty passwords"""
    findings = []
    
    valid_users = ['admin', 'gordonb', 'pablo', 'smithy']
    
    for user in valid_users:
        try:
            response_data, error = test_login_response(session, base_url, user, '')
            
            if error:
                continue
                
            if response_data:
                # Check if login was somehow successful or gave different response
                content = response_data['content'].lower()
                success_indicators = ['welcome', 'dashboard', 'logout', 'index.php']
                
                for indicator in success_indicators:
                    if indicator in content:
                        findings.append({
                            'vulnerability': 'Empty Password Authentication Success',
                            'username': user,
                            'evidence': f"User '{user}' authenticated with empty password",
                            'severity': 'High'
                        })
                        break
        except Exception as e:
            pass
    
    return findings

def test_sequential_usernames(session, base_url):
    """Test sequential username patterns"""
    findings = []
    
    # Test common sequential patterns
    patterns = [
        ['user1', 'user2', 'user3'],
        ['test1', 'test2', 'test3']
    ]
    
    for pattern in patterns:
        responses = {}
        for username in pattern:
            response_data, error = test_login_response(session, base_url, username, 'wrongpassword')
            if not error and response_data:
                responses[username] = response_data
            time.sleep(0.1)  # Small delay to be respectful
        
        # Analyze response patterns for this sequence
        if len(responses) > 1:
            # Compare content lengths
            lengths = [data['content_length'] for data in responses.values()]
            if len(set(lengths)) > 1:
                # Different lengths might indicate enumeration
                findings.append({
                    'vulnerability': 'Sequential Username Pattern Response Differences',
                    'username': f"Pattern: {pattern[0]}-{pattern[-1]}",
                    'evidence': f"Different response lengths for sequential usernames suggest enumeration possibility",
                    'severity': 'Medium'
                })
    
    return findings

def test_common_usernames_bruteforce(session, base_url):
    """Test common usernames with common passwords"""
    findings = []
    valid_accounts = []
    
    print("[*] Testing common username/password combinations...")
    
    # Common usernames
    common_usernames = [
        'admin', 'administrator', 'root', 'user', 'test',
        'guest', 'info', 'adm', 'mysql', 'webmaster',
        'gordonb', 'pablo', 'smithy', 'john', 'dave',
        'manager', 'operator', 'supervisor', 'support'
    ]
    
    # Common passwords
    common_passwords = [
        'password', 'admin', '123456', 'password123',
        'admin123', 'guest', 'test', 'abc123',
        'qwerty', '12345678', 'welcome', 'login'
    ]
    
    tested_combinations = 0
    max_tests = 30  # Limit to be respectful
    
    for username in common_usernames:
        if tested_combinations >= max_tests:
            break
            
        for password in common_passwords:
            if tested_combinations >= max_tests:
                break
                
            try:
                response_data, error = test_login_response(session, base_url, username, password)
                tested_combinations += 1
                
                if error:
                    continue
                    
                if response_data:
                    # Check if login was successful
                    content = response_data['content'].lower()
                    location = response_data.get('location', '').lower()
                    
                    # Successful login indicators
                    success_indicators = [
                        'welcome', 'dashboard', 'logout', 'success',
                        'index.php', 'main.php', 'home'
                    ]
                    
                    is_successful = False
                    for indicator in success_indicators:
                        if indicator in content or indicator in location:
                            is_successful = True
                            break
                    
                    if is_successful:
                        valid_accounts.append((username, password))
                        findings.append({
                            'vulnerability': 'Guessable Account Found',
                            'username': f"{username}:{password}",
                            'evidence': f"Successful login with common credentials",
                            'severity': 'High'
                        })
                        break  # Move to next username once we find a valid one
                        
            except Exception as e:
                pass
            
            time.sleep(0.1)  # Small delay to be respectful
    
    if valid_accounts:
        print(f"[+] Found {len(valid_accounts)} valid accounts:")
        for username, password in valid_accounts:
            print(f"    - {username}:{password}")
    
    return findings

def generate_html_report(findings, response_analysis, analysis_details, base_url):
    """Generate OSCP-style HTML report"""
    
    # Count severity levels
    high_count = len([f for f in findings if f['severity'] == 'High'])
    medium_count = len([f for f in findings if f['severity'] == 'Medium'])
    low_count = len([f for f in findings if f['severity'] == 'Low'])
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - OTG-IDENT-004</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #1e1e1e;
            color: #d4d4d4;
            margin: 0;
            padding: 20px;
        }}
        .header {{
            background-color: #2d2d30;
            padding: 20px;
            border-left: 4px solid #4ec9b0;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #4ec9b0;
            margin: 0;
            font-size: 24px;
        }}
        .header p {{
            margin: 5px 0;
            color: #9cdcfe;
        }}
        .section {{
            background-color: #2d2d30;
            margin-bottom: 20px;
            padding: 20px;
            border-left: 3px solid #c586c0;
        }}
        .section-title {{
            color: #4ec9b0;
            font-size: 20px;
            margin-top: 0;
            margin-bottom: 15px;
        }}
        .finding-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        .finding-table th {{
            background-color: #3c3c3c;
            color: #4ec9b0;
            padding: 12px;
            text-align: left;
            border: 1px solid #555;
        }}
        .finding-table td {{
            padding: 10px;
            border: 1px solid #555;
            vertical-align: top;
        }}
        .high {{ color: #f48771; }}
        .medium {{ color: #e2c08d; }}
        .low {{ color: #75beff; }}
        .summary-box {{
            background-color: #3c3c3c;
            padding: 15px;
            margin: 15px 0;
            border-left: 3px solid #4ec9b0;
        }}
        pre {{
            background-color: #3c3c3c;
            padding: 15px;
            overflow-x: auto;
            border: 1px solid #555;
            color: #d4d4d4;
        }}
        .evidence {{
            font-size: 12px;
            white-space: pre-wrap;
        }}
        .response-analysis {{
            background-color: #3c3c3c;
            padding: 15px;
            margin: 15px 0;
            border-left: 3px solid #4ec9b0;
        }}
        .analysis-details {{
            background-color: #252526;
            padding: 10px;
            margin: 10px 0;
            border-left: 2px solid #569cd6;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>OWASP Security Assessment Report</h1>
        <p><strong>Target:</strong> {base_url}</p>
        <p><strong>Test ID:</strong> OTG-IDENT-004 - Account Enumeration and Guessable User Account</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <p>This assessment evaluated the account enumeration and guessable user account vulnerabilities 
        of the DVWA application according to OWASP Testing Guide v4 - OTG-IDENT-004. The test focused 
        on identifying information leakage through login responses that could allow an attacker to enumerate 
        valid usernames and subsequently perform targeted brute force attacks.</p>
        
        <div class="summary-box">
            <p><strong>Findings Summary:</strong></p>
            <p><span class="high">High Severity:</span> {high_count} findings</p>
            <p><span class="medium">Medium Severity:</span> {medium_count} findings</p>
            <p><span class="low">Low Severity:</span> {low_count} findings</p>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Methodology</h2>
        <p>The testing methodology followed OWASP Testing Guide v4 guidelines for testing account enumeration:</p>
        <ul>
            <li>Analysis of HTTP responses for valid user + valid password</li>
            <li>Analysis of HTTP responses for valid user + wrong password</li>
            <li>Analysis of HTTP responses for invalid user + invalid password</li>
            <li>Comparison of response characteristics (status codes, content length, timing, titles)</li>
            <li>URI probing for user directory enumeration</li>
            <li>Testing empty password authentication</li>
            <li>Sequential username pattern analysis</li>
            <li>Recovery facility enumeration testing</li>
            <li>Common username/password brute force testing</li>
        </ul>
    </div>

    <div class="section">
        <h2 class="section-title">Response Analysis Details</h2>
        <div class="response-analysis">
            <p><strong>Detailed response analysis:</strong></p>"""
    
    for detail in analysis_details:
        html_content += f"<div class='analysis-details'>{detail}</div>"
    
    html_content += f"""
            <p>Analysis of response differences helps identify potential enumeration vulnerabilities.</p>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Test Results</h2>
        <table class="finding-table">
            <tr>
                <th>Vulnerability</th>
                <th>Target/Username</th>
                <th>Evidence</th>
                <th>Severity</th>
            </tr>"""
    
    if findings:
        for finding in findings:
            severity_class = finding['severity'].lower()
            html_content += f"""
            <tr>
                <td>{finding['vulnerability']}</td>
                <td>{finding['username']}</td>
                <td class="evidence">{finding['evidence']}</td>
                <td class="{severity_class}">{finding['severity']}</td>
            </tr>"""
    else:
        html_content += """
            <tr>
                <td colspan="4" style="text-align: center;">No account enumeration vulnerabilities found - DVWA is properly configured</td>
            </tr>"""
    
    html_content += f"""
        </table>
    </div>

    <div class="section">
        <h2 class="section-title">Risk Assessment</h2>
        <p>Account enumeration vulnerabilities can lead to targeted attacks against valid user accounts. 
        When no vulnerabilities are found, it indicates that the application properly implements consistent 
        responses for all authentication attempts, making it difficult for attackers to distinguish between 
        valid and invalid users.</p>
    </div>

    <div class="section">
        <h2 class="section-title">Recommendations</h2>
        <ol>
            <li>Maintain consistent error messages for both valid and invalid login attempts</li>
            <li>Ensure uniform response times regardless of username validity</li>
            <li>Use identical response content length for all authentication failures</li>
            <li>Continue implementing account lockout mechanisms after failed login attempts</li>
            <li>Maintain strong password policies and consider multi-factor authentication</li>
            <li>Monitor and log authentication attempts for suspicious activity</li>
            <li>Ensure password recovery mechanisms do not leak user existence information</li>
        </ol>
    </div>

    <div class="section">
        <h2 class="section-title">References</h2>
        <ul>
            <li>OWASP Testing Guide v4 - OTG-IDENT-004: Testing for Account Enumeration and Guessable User Account</li>
            <li>OWASP Top 10 - A07:2021-Identification and Authentication Failures</li>
            <li>CWE-200: Exposure of Sensitive Information to an Unauthorized Actor</li>
            <li>CWE-287: Improper Authentication</li>
        </ul>
    </div>
</body>
</html>"""
    
    # Save the report
    with open("OTG-IDENT-004_Report.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print("HTML report generated: OTG-IDENT-004_Report.html")

def main():
    # Configuration
    base_url = "http://localhost/dvwa"
    
    # Create session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    print("[*] Starting OTG-IDENT-004 Account Enumeration Test")
    print(f"[*] Target: {base_url}")
    print("[!] WARNING: This script is for educational and authorized testing only")
    
    # Check if DVWA is accessible
    try:
        response = session.get(base_url, timeout=10)
        if response.status_code != 200:
            print("[-] DVWA is not accessible. Please ensure XAMPP is running and DVWA is installed.")
            return
        print("[+] DVWA is accessible")
    except Exception as e:
        print(f"[-] Error connecting to DVWA: {e}")
        return
    
    # Perform the three core tests as per OWASP methodology
    print("[*] Performing core OWASP account enumeration tests...")
    
    # Test 1: Valid user with valid password
    valid_good, error1 = test_valid_user_valid_password(session, base_url)
    if error1:
        print(f"[-] Error in valid user/valid password test: {error1}")
    
    time.sleep(1)
    
    # Test 2: Valid user with wrong password
    valid_bad, error2 = test_valid_user_wrong_password(session, base_url)
    if error2:
        print(f"[-] Error in valid user/wrong password test: {error2}")
    
    time.sleep(1)
    
    # Test 3: Invalid user with invalid password
    invalid_bad, error3 = test_invalid_user_invalid_password(session, base_url)
    if error3:
        print(f"[-] Error in invalid user/invalid password test: {error3}")
    
    # Analyze the three core responses
    print("[*] Analyzing response differences...")
    difference_findings, analysis_details = analyze_response_differences(valid_good, valid_bad, invalid_bad)
    
    # Collect additional findings
    all_findings = []
    all_findings.extend(difference_findings)
    
    print("[*] Testing URI probing...")
    uri_findings = test_uri_probing(session, base_url)
    all_findings.extend(uri_findings)
    
    print("[*] Testing recovery facility...")
    recovery_findings = test_recovery_facility(session, base_url)
    all_findings.extend(recovery_findings)
    
    print("[*] Testing empty password authentication...")
    empty_password_findings = test_empty_password(session, base_url)
    all_findings.extend(empty_password_findings)
    
    print("[*] Testing sequential username patterns...")
    sequential_findings = test_sequential_usernames(session, base_url)
    all_findings.extend(sequential_findings)
    
    print("[*] Testing common username/password combinations...")
    bruteforce_findings = test_common_usernames_bruteforce(session, base_url)
    all_findings.extend(bruteforce_findings)
    
    # Generate report
    print("[*] Generating HTML report...")
    generate_html_report(all_findings, difference_findings, analysis_details, base_url)
    
    # Summary
    high_count = len([f for f in all_findings if f['severity'] == 'High'])
    medium_count = len([f for f in all_findings if f['severity'] == 'Medium'])
    low_count = len([f for f in all_findings if f['severity'] == 'Low'])
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    if len(all_findings) == 0:
        print("✅ NO ACCOUNT ENUMERATION VULNERABILITIES FOUND")
        print("   DVWA is properly configured to prevent user enumeration")
    else:
        print(f"⚠️  HIGH SEVERITY ISSUES:   {high_count}")
        print(f"⚠️  MEDIUM SEVERITY ISSUES: {medium_count}")
        print(f"⚠️  LOW SEVERITY ISSUES:    {low_count}")
        print(f"🔍 TOTAL FINDINGS:         {len(all_findings)}")
    print("="*60)
    print("Report saved as: OTG-IDENT-004_Report.html")
    print("\n[!] Remember: This is for educational purposes only.")
    print("[!] Always obtain proper authorization before testing.")

if __name__ == "__main__":
    main()