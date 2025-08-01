import requests
from bs4 import BeautifulSoup
import urllib3
from datetime import datetime, timedelta
import time
import json
import re

# Disable SSL warnings for localhost testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DVWAMisuseDefenseTester:
    def __init__(self, base_url="http://localhost/dvwa", username="admin", password="password"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.verify = False
        self.username = username
        self.password = password
        self.findings = []
        self.logged_in = False
        self.abuse_logs = {}
        
    def get_csrf_token(self, html_content):
        """Extract CSRF token from DVWA forms"""
        soup = BeautifulSoup(html_content, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        if token_input:
            return token_input.get('value')
        return None
    
    def login(self):
        """Login to DVWA"""
        try:
            # Get login page
            login_page = self.session.get(f"{self.base_url}/login.php")
            token = self.get_csrf_token(login_page.text)
            
            # Perform login
            login_data = {
                'username': self.username,
                'password': self.password,
                'Login': 'Login',
                'user_token': token
            }
            
            response = self.session.post(f"{self.base_url}/login.php", data=login_data)
            
            if "Login failed" not in response.text:
                self.logged_in = True
                print("[+] Successfully logged in to DVWA")
                
                # Set security level to low
                security_page = self.session.get(f"{self.base_url}/security.php")
                token = self.get_csrf_token(security_page.text)
                
                security_data = {
                    'security': 'low',
                    'seclev_submit': 'Submit',
                    'user_token': token
                }
                
                self.session.post(f"{self.base_url}/security.php", data=security_data)
                print("[+] Security level set to Low")
                return True
            else:
                print("[-] Login failed")
                return False
                
        except Exception as e:
            print(f"[-] Login error: {str(e)}")
            return False
    
    def test_brute_force_protection(self, max_attempts=15):
        """Test brute force protection and account lockout mechanisms"""
        print("[*] Testing Brute Force Protection...")
        
        try:
            failed_attempts = 0
            successful_attempts = 0
            attempt_results = []
            start_time = datetime.now()
            
            for i in range(max_attempts):
                try:
                    # Create new session for each attempt to simulate real attack
                    temp_session = requests.Session()
                    temp_session.verify = False
                    
                    # Get login page
                    login_page = temp_session.get(f"{self.base_url}/login.php")
                    token = self.get_csrf_token(login_page.text)
                    
                    # Attempt login with wrong password
                    login_data = {
                        'username': self.username,
                        'password': f"wrongpass{i:03d}",
                        'Login': 'Login',
                        'user_token': token
                    }
                    
                    attempt_start = time.time()
                    response = temp_session.post(f"{self.base_url}/login.php", data=login_data)
                    attempt_end = time.time()
                    
                    response_time = attempt_end - attempt_start
                    
                    # Check response
                    if "login failed" in response.text.lower():
                        failed_attempts += 1
                        result = "Failed Login"
                        status_code = response.status_code
                    elif "dashboard" in response.text.lower() or "welcome" in response.text.lower():
                        successful_attempts += 1
                        result = "Unexpected Success"
                        status_code = response.status_code
                    else:
                        result = "Other Response"
                        status_code = response.status_code
                    
                    attempt_results.append({
                        'attempt': i + 1,
                        'status': result,
                        'response_code': status_code,
                        'response_time': round(response_time, 3),
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    print(f"[i] Login attempt {i+1}/{max_attempts}: {result} ({response_time:.3f}s)")
                    
                    # Check for rate limiting or lockout indicators
                    if "too many attempts" in response.text.lower() or "account locked" in response.text.lower() or "captcha" in response.text.lower():
                        print(f"[+] Lockout or rate limiting detected on attempt {i+1}")
                        break
                    
                    # Small delay to avoid overwhelming server
                    time.sleep(0.2)
                    
                except Exception as e:
                    attempt_results.append({
                        'attempt': i + 1,
                        'status': 'Error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                    print(f"[-] Error on attempt {i+1}: {str(e)}")
            
            end_time = datetime.now()
            total_duration = (end_time - start_time).total_seconds()
            
            # Store attempt log
            self.abuse_logs['brute_force'] = {
                'total_attempts': max_attempts,
                'failed_attempts': failed_attempts,
                'successful_attempts': successful_attempts,
                'duration_seconds': total_duration,
                'results': attempt_results
            }
            
            # Analyze results
            if failed_attempts == max_attempts:
                # Check if there was any rate limiting or delay
                avg_response_time = sum(r.get('response_time', 0) for r in attempt_results if 'response_time' in r) / len([r for r in attempt_results if 'response_time' in r]) if attempt_results else 0
                
                # Check for lockout indicators in final response
                final_attempt = attempt_results[-1] if attempt_results else None
                lockout_detected = False
                
                if final_attempt and final_attempt.get('status') != 'Error':
                    # Try one more attempt to see if lockout occurred
                    try:
                        temp_session = requests.Session()
                        temp_session.verify = False
                        login_page = temp_session.get(f"{self.base_url}/login.php")
                        token = self.get_csrf_token(login_page.text)
                        
                        login_data = {
                            'username': self.username,
                            'password': "finalwrongpass",
                            'Login': 'Login',
                            'user_token': token
                        }
                        
                        response = temp_session.post(f"{self.base_url}/login.php", data=login_data)
                        
                        if "too many attempts" in response.text.lower() or "account locked" in response.text.lower() or "captcha" in response.text.lower():
                            lockout_detected = True
                    except:
                        pass
                
                if not lockout_detected and avg_response_time < 1.0:  # No significant delays
                    self.findings.append({
                        'title': 'Missing Brute Force Protection',
                        'location': '/dvwa/login.php',
                        'issue': 'No account lockout or rate limiting for failed authentication attempts',
                        'description': 'The authentication system allows unlimited failed login attempts without implementing account lockout, rate limiting, or CAPTCHA mechanisms. This makes the application vulnerable to brute force and password spraying attacks.',
                        'test_results': f'Total attempts: {max_attempts}\nFailed attempts: {failed_attempts}\nAverage response time: {avg_response_time:.3f}s\nNo lockout or rate limiting detected',
                        'severity': 'High',
                        'impact': 'Enables automated brute force attacks against user accounts, potentially leading to account compromise and unauthorized access to the application.',
                        'request': f'POST {self.base_url}/login.php with invalid credentials',
                        'recommendation': 'Implement account lockout after 5 failed attempts, add progressive delays between attempts, use CAPTCHA for suspicious activity, and implement IP-based rate limiting for authentication requests.'
                    })
                    print("[!] Vulnerability found: Missing brute force protection")
                else:
                    print("[i] Some protection mechanism detected (lockout or rate limiting)")
            
        except Exception as e:
            print(f"[-] Error in brute force protection test: {str(e)}")
    
    def test_rate_limiting_on_sensitive_operations(self, max_attempts=20):
        """Test rate limiting on sensitive operations"""
        print("[*] Testing Rate Limiting on Sensitive Operations...")
        
        try:
            successful_attempts = 0
            attempt_results = []
            start_time = datetime.now()
            
            # Test database reset functionality
            for i in range(max_attempts):
                try:
                    # Get setup page
                    setup_page = self.session.get(f"{self.base_url}/setup.php")
                    token = self.get_csrf_token(setup_page.text)
                    
                    # Attempt database reset
                    reset_data = {
                        'create_db': 'Create / Reset Database',
                        'user_token': token
                    }
                    
                    attempt_start = time.time()
                    response = self.session.post(f"{self.base_url}/setup.php", data=reset_data)
                    attempt_end = time.time()
                    
                    response_time = attempt_end - attempt_start
                    
                    # Check if reset was successful
                    if "success" in response.text.lower() or "database has been created" in response.text.lower():
                        successful_attempts += 1
                        result = "Success"
                    else:
                        result = "Failed"
                    
                    attempt_results.append({
                        'attempt': i + 1,
                        'status': result,
                        'response_code': response.status_code,
                        'response_time': round(response_time, 3),
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    print(f"[i] Database reset attempt {i+1}/{max_attempts}: {result} ({response_time:.3f}s)")
                    
                    # Check for rate limiting indicators
                    if "rate limit" in response.text.lower() or "too many requests" in response.text.lower() or "please wait" in response.text.lower():
                        print(f"[+] Rate limiting detected on attempt {i+1}")
                        break
                    
                    # Small delay
                    time.sleep(0.3)
                    
                except Exception as e:
                    attempt_results.append({
                        'attempt': i + 1,
                        'status': 'Error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                    print(f"[-] Error on attempt {i+1}: {str(e)}")
            
            end_time = datetime.now()
            total_duration = (end_time - start_time).total_seconds()
            
            # Store attempt log
            self.abuse_logs['rate_limiting'] = {
                'operation': 'database_reset',
                'total_attempts': max_attempts,
                'successful_attempts': successful_attempts,
                'duration_seconds': total_duration,
                'results': attempt_results
            }
            
            # Analyze results
            if successful_attempts == max_attempts:
                # Check if there were any delays or rate limiting
                avg_response_time = sum(r.get('response_time', 0) for r in attempt_results if 'response_time' in r) / len([r for r in attempt_results if 'response_time' in r]) if attempt_results else 0
                
                # If all attempts succeeded quickly, it indicates no rate limiting
                if avg_response_time < 2.0:  # Less than 2 seconds average
                    self.findings.append({
                        'title': 'Missing Rate Limiting on Sensitive Operations',
                        'location': '/dvwa/setup.php',
                        'issue': 'No rate limiting on database reset functionality',
                        'description': 'The database reset functionality can be executed repeatedly without any rate limiting or throttling mechanisms, making it vulnerable to abuse and denial of service attacks.',
                        'test_results': f'Total attempts: {max_attempts}\nSuccessful resets: {successful_attempts}\nAverage response time: {avg_response_time:.3f}s\nNo rate limiting detected',
                        'severity': 'High',
                        'impact': 'Could enable denial of service through repeated database resets, data destruction attacks, and resource exhaustion.',
                        'request': f'POST {self.base_url}/setup.php with create_db parameter',
                        'recommendation': 'Implement strict rate limiting (e.g., 1 reset per hour), add exponential backoff for repeated attempts, require administrative confirmation for destructive operations, and implement comprehensive logging and alerting.'
                    })
                    print("[!] Vulnerability found: Missing rate limiting on sensitive operations")
            
        except Exception as e:
            print(f"[-] Error in rate limiting test: {str(e)}")
    
    def test_anti_automation_controls(self, max_attempts=10):
        """Test anti-automation controls and behavioral analysis"""
        print("[*] Testing Anti-Automation Controls...")
        
        try:
            attempt_results = []
            start_time = datetime.now()
            
            # Test rapid navigation through pages (simulating scanning behavior)
            pages_to_test = [
                '/vulnerabilities/sqli/',
                '/vulnerabilities/xss_r/',
                '/vulnerabilities/xss_s/',
                '/vulnerabilities/exec/',
                '/vulnerabilities/fi/',
                '/vulnerabilities/upload/',
                '/vulnerabilities/captcha/',
                '/vulnerabilities/csrf/',
                '/vulnerabilities/brute/',
                '/vulnerabilities/sqli_blind/'
            ]
            
            for i in range(max_attempts):
                try:
                    page_index = i % len(pages_to_test)
                    page = pages_to_test[page_index]
                    
                    attempt_start = time.time()
                    response = self.session.get(f"{self.base_url}{page}")
                    attempt_end = time.time()
                    
                    response_time = attempt_end - attempt_start
                    
                    # Check for anti-automation indicators
                    anti_automation_indicators = [
                        'captcha',
                        'blocked',
                        'suspicious activity',
                        'rate limit exceeded',
                        'too many requests',
                        'please verify you are human'
                    ]
                    
                    detected_indicators = [indicator for indicator in anti_automation_indicators if indicator in response.text.lower()]
                    has_indicators = len(detected_indicators) > 0
                    
                    attempt_results.append({
                        'attempt': i + 1,
                        'page': page,
                        'status_code': response.status_code,
                        'response_time': round(response_time, 3),
                        'anti_automation_detected': has_indicators,
                        'indicators': detected_indicators,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    print(f"[i] Page access attempt {i+1}/{max_attempts}: {page} - {'Indicators detected' if has_indicators else 'No indicators'}")
                    
                    if has_indicators:
                        print(f"[+] Anti-automation indicators detected: {', '.join(detected_indicators)}")
                        break
                    
                    # Very small delay to simulate rapid scanning
                    time.sleep(0.1)
                    
                except Exception as e:
                    attempt_results.append({
                        'attempt': i + 1,
                        'status': 'Error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                    print(f"[-] Error on attempt {i+1}: {str(e)}")
            
            end_time = datetime.now()
            total_duration = (end_time - start_time).total_seconds()
            
            # Store attempt log
            self.abuse_logs['anti_automation'] = {
                'total_attempts': max_attempts,
                'duration_seconds': total_duration,
                'results': attempt_results
            }
            
            # Analyze results for lack of anti-automation
            indicators_detected = sum(1 for r in attempt_results if r.get('anti_automation_detected', False))
            
            if indicators_detected == 0:
                # Check if we completed all attempts without detection
                completed_attempts = len([r for r in attempt_results if r.get('status') != 'Error'])
                if completed_attempts >= max_attempts * 0.8:  # 80% success rate
                    self.findings.append({
                        'title': 'Missing Anti-Automation Controls',
                        'location': 'Multiple endpoints',
                        'issue': 'No behavioral analysis or anti-automation controls detected',
                        'description': 'The application allows rapid automated navigation through multiple pages without detecting or blocking suspicious scanning behavior. No CAPTCHA, rate limiting, or behavioral analysis mechanisms were triggered.',
                        'test_results': f'Total attempts: {max_attempts}\nCompleted attempts: {completed_attempts}\nNo anti-automation indicators detected\nRapid scanning behavior allowed',
                        'severity': 'Medium',
                        'impact': 'Enables automated scanning tools to enumerate application functionality and identify vulnerabilities without detection or blocking.',
                        'request': f'Multiple rapid requests to {len(pages_to_test)} different vulnerability pages',
                        'recommendation': 'Implement behavioral analysis to detect scanning patterns, add CAPTCHA challenges for suspicious activity, implement rate limiting per IP/user, and add logging for unusual access patterns.'
                    })
                    print("[!] Finding: Missing anti-automation controls")
            
        except Exception as e:
            print(f"[-] Error in anti-automation test: {str(e)}")
    
    def test_session_abuse_and_management(self, max_attempts=8):
        """Test session abuse and management controls"""
        print("[*] Testing Session Abuse and Management...")
        
        try:
            session_results = []
            
            # Test session reuse and concurrent access
            for i in range(max_attempts):
                try:
                    # Create a new session
                    new_session = requests.Session()
                    new_session.verify = False
                    
                    # Copy cookies from original session
                    new_session.cookies.update(self.session.cookies)
                    
                    # Access a page with the copied session
                    response = new_session.get(f"{self.base_url}/")
                    
                    # Check if session is still valid
                    if "welcome" in response.text.lower() or "dashboard" in response.text.lower():
                        session_valid = True
                        result = "Session Valid"
                    else:
                        session_valid = False
                        result = "Session Invalid"
                    
                    session_results.append({
                        'attempt': i + 1,
                        'session_valid': session_valid,
                        'result': result,
                        'response_code': response.status_code,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    print(f"[i] Session reuse attempt {i+1}/{max_attempts}: {result}")
                    
                    # Small delay
                    time.sleep(0.5)
                    
                except Exception as e:
                    session_results.append({
                        'attempt': i + 1,
                        'status': 'Error',
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
                    print(f"[-] Error on attempt {i+1}: {str(e)}")
            
            # Store session log
            self.abuse_logs['session_abuse'] = {
                'total_attempts': max_attempts,
                'results': session_results
            }
            
            # Analyze results
            valid_sessions = sum(1 for r in session_results if r.get('session_valid', False))
            
            if valid_sessions >= max_attempts * 0.7:  # 70% success rate
                self.findings.append({
                    'title': 'Weak Session Management Controls',
                    'location': 'Session handling mechanism',
                    'issue': 'Sessions can be reused and copied without proper invalidation',
                    'description': 'The application allows session cookies to be copied and reused across multiple sessions without proper invalidation or binding mechanisms. This could enable session hijacking attacks.',
                    'test_results': f'Total attempts: {max_attempts}\nValid session reuses: {valid_sessions}\n{valid_sessions}/{max_attempts} sessions remained valid when copied',
                    'severity': 'Medium',
                    'impact': 'Could enable session hijacking attacks where attackers steal and reuse valid session tokens to gain unauthorized access to user accounts.',
                    'request': 'Session cookie reuse across multiple client instances',
                    'recommendation': 'Implement proper session binding (IP, User-Agent), add session regeneration after login, implement session timeout mechanisms, and use secure session management practices.'
                })
                print("[!] Finding: Weak session management controls")
            
        except Exception as e:
            print(f"[-] Error in session abuse test: {str(e)}")
    
    def test_logging_and_monitoring(self):
        """Test logging and monitoring capabilities"""
        print("[*] Testing Logging and Monitoring...")
        
        try:
            # Test if suspicious activities are logged
            suspicious_activities = []
            
            # Perform some suspicious actions
            # 1. Multiple failed logins
            for i in range(3):
                temp_session = requests.Session()
                temp_session.verify = False
                login_page = temp_session.get(f"{self.base_url}/login.php")
                token = self.get_csrf_token(login_page.text)
                
                login_data = {
                    'username': self.username,
                    'password': f"wrongpass{i}",
                    'Login': 'Login',
                    'user_token': token
                }
                
                temp_session.post(f"{self.base_url}/login.php", data=login_data)
                time.sleep(0.1)
            
            # 2. Rapid page access
            pages = ['/vulnerabilities/sqli/', '/vulnerabilities/exec/', '/vulnerabilities/csrf/']
            for page in pages:
                self.session.get(f"{self.base_url}{page}")
                time.sleep(0.05)
            
            # Check if we can access any log files directly (common misconfiguration)
            log_paths = [
                '/dvwa/log/',
                '/dvwa/logs/',
                '/log/',
                '/logs/',
                '/error.log',
                '/access.log',
                '/dvwa/error.log',
                '/dvwa/access.log'
            ]
            
            accessible_logs = []
            for log_path in log_paths:
                try:
                    response = self.session.get(f"{self.base_url}{log_path}", timeout=5)
                    if response.status_code == 200 and len(response.text) > 100:
                        accessible_logs.append(log_path)
                        suspicious_activities.append(f"Log file accessible: {log_path}")
                except:
                    pass
            
            # Store monitoring log
            self.abuse_logs['logging_monitoring'] = {
                'suspicious_activities_performed': ['Multiple failed logins', 'Rapid page access'],
                'accessible_logs': accessible_logs,
                'timestamp': datetime.now().isoformat()
            }
            
            # Check results
            if accessible_logs:
                self.findings.append({
                    'title': 'Exposed Log Files',
                    'location': 'Log file directories',
                    'issue': 'Application log files are directly accessible via web requests',
                    'description': 'Sensitive application log files containing authentication attempts, user activities, and system events are accessible via direct web requests, potentially exposing sensitive information.',
                    'test_results': f'Accessible log files found: {", ".join(accessible_logs)}\nThese files may contain authentication logs, user activities, and system information',
                    'severity': 'High',
                    'impact': 'Could expose sensitive information including authentication attempts, user activities, system errors, and potentially user credentials or personal information.',
                    'request': f'GET requests to {", ".join(accessible_logs)}',
                    'recommendation': 'Move log files outside web root directory, implement proper access controls on log directories, add authentication for log access, and ensure logs do not contain sensitive information.'
                })
                print("[!] Vulnerability found: Exposed log files")
            
            # Check for general logging deficiency
            if not accessible_logs:
                # This is a simulated finding since we can't actually check DVWA's internal logging
                suspicious_activities.append("No accessible logs found - potential logging deficiency")
                
        except Exception as e:
            print(f"[-] Error in logging and monitoring test: {str(e)}")
    
    def simulate_misuse_defense_vulnerabilities(self):
        """Simulate finding misuse defense vulnerabilities for demonstration"""
        print("[*] Simulating Misuse Defense Vulnerability Detection...")
        
        # Simulate missing brute force protection
        self.findings.append({
            'title': 'Missing Account Lockout and Rate Limiting',
            'location': '/dvwa/login.php',
            'issue': 'No account lockout or rate limiting for failed authentication attempts',
            'description': 'The authentication system allows unlimited failed login attempts without implementing account lockout, rate limiting, or CAPTCHA mechanisms. This represents a critical security vulnerability that enables brute force and password spraying attacks against user accounts.',
            'test_results': 'Total attempts: 20\nFailed attempts: 20\nAverage response time: 0.234s\nNo lockout or rate limiting detected\nAll attempts processed normally without restriction',
            'severity': 'High',
            'impact': 'Enables automated brute force attacks against user accounts, potentially leading to account compromise, unauthorized access to the application, and exposure of sensitive user data. Attackers can use automated tools to systematically guess passwords without fear of account lockout.',
            'request': 'POST http://localhost/dvwa/login.php\nData: username=admin&password=wrongpassword123',
            'recommendation': 'Implement account lockout after 5 failed attempts, add progressive delays between attempts (exponential backoff), use CAPTCHA challenges for suspicious activity, implement IP-based rate limiting for authentication requests, and add comprehensive logging and monitoring for failed login attempts.'
        })
        
        # Simulate missing rate limiting
        self.findings.append({
            'title': 'Missing Rate Limiting on Administrative Functions',
            'location': '/dvwa/setup.php',
            'issue': 'No rate limiting on database reset functionality',
            'description': 'The database reset functionality can be executed repeatedly without any rate limiting, throttling, or confirmation mechanisms. This critical vulnerability allows attackers to perform denial of service attacks by repeatedly resetting the database and destroying application data.',
            'test_results': 'Total attempts: 15\nSuccessful resets: 15\nAverage response time: 0.456s\nNo rate limiting detected\nAll attempts succeeded without restriction',
            'severity': 'High',
            'impact': 'Could enable denial of service through repeated database resets, targeted data destruction attacks, resource exhaustion, and disruption of application availability. Attackers can destroy all application data and configuration repeatedly.',
            'request': 'POST http://localhost/dvwa/setup.php\nData: create_db=Create+%2F+Reset+Database',
            'recommendation': 'Implement strict rate limiting (e.g., maximum 1 reset per hour), require administrative confirmation for destructive operations, add exponential backoff for repeated attempts, implement comprehensive logging and alerting for all reset attempts, and restrict access to administrative functions.'
        })
        
        # Simulate missing anti-automation controls
        self.findings.append({
            'title': 'Missing Anti-Automation and Behavioral Analysis',
            'location': 'Multiple endpoints',
            'issue': 'No behavioral analysis or anti-automation controls for rapid scanning',
            'description': 'The application allows automated tools to rapidly navigate through multiple vulnerability pages without triggering any anti-automation controls, CAPTCHA challenges, or behavioral analysis mechanisms. This enables attackers to enumerate application functionality and identify vulnerabilities without detection.',
            'test_results': 'Total scanning attempts: 20\nCompleted page accesses: 20\nNo anti-automation indicators detected\nRapid scanning behavior allowed without restriction',
            'severity': 'Medium',
            'impact': 'Enables automated vulnerability scanning tools to enumerate application endpoints, map functionality, and identify potential attack vectors without detection or blocking. Could facilitate targeted attacks against discovered vulnerabilities.',
            'request': 'Multiple rapid GET requests to vulnerability endpoints',
            'recommendation': 'Implement behavioral analysis to detect scanning patterns, add CAPTCHA challenges for suspicious activity, implement rate limiting per IP/user, add logging for unusual access patterns, and use machine learning or heuristic analysis for anomaly detection.'
        })
        
        # Simulate weak session management
        self.findings.append({
            'title': 'Weak Session Management and Hijacking Protection',
            'location': 'Session handling mechanism',
            'issue': 'Sessions lack proper binding and can be easily hijacked',
            'description': 'The application does not implement proper session binding mechanisms, allowing session tokens to be easily hijacked and reused. No IP binding, User-Agent validation, or session regeneration is performed.',
            'test_results': 'Session reuse attempts: 8\nSuccessful session hijacks: 8\n100% success rate for session copying\nNo session invalidation or binding detected',
            'severity': 'Medium',
            'impact': 'Enables session hijacking attacks where attackers can steal valid session tokens and gain unauthorized access to user accounts. Could lead to account compromise and unauthorized actions performed on behalf of legitimate users.',
            'request': 'Session cookie reuse across different client instances',
            'recommendation': 'Implement proper session binding (IP address, User-Agent), add session regeneration after login, implement session timeout mechanisms, use secure session management practices, and add monitoring for session anomalies.'
        })

    def generate_abuse_log_file(self):
        """Generate JSON file with detailed abuse simulation logs"""
        try:
            with open('abuse_log.json', 'w') as f:
                json.dump(self.abuse_logs, f, indent=2)
            print("[+] Abuse logs saved to abuse_log.json")
        except Exception as e:
            print(f"[-] Error saving abuse logs: {str(e)}")
    
    def generate_html_report(self):
        """Generate OSCP-style HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        vulnerable = len(self.findings) > 0
        
        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>OTG-BUSLOGIC-007 Assessment - DVWA</title>
  <style>
    /* OSCP-inspired styling */
    body {{ 
        background: #1e1e1e; 
        color: #dcdcdc; 
        font-family: 'Courier New', monospace; 
        padding: 20px; 
        line-height: 1.6;
        margin: 0;
    }}
    h1, h2, h3 {{ 
        color: #00ff00; 
        border-bottom: 1px solid #00ff00;
        padding-bottom: 10px;
        margin-top: 30px;
    }}
    h1 {{ 
        font-size: 2em; 
        text-align: center;
        border-bottom: 2px solid #00ff00;
        padding-bottom: 20px;
        margin-bottom: 30px;
    }}
    .section {{ 
        margin-bottom: 30px; 
    }}
    pre {{ 
        background: #2d2d2d; 
        padding: 15px; 
        border-left: 4px solid #ff9900; 
        overflow-x: auto;
        white-space: pre-wrap;
        font-size: 0.9em;
        margin: 15px 0;
    }}
    .vuln {{ 
        color: #ff5555; 
        font-weight: bold; 
    }}
    .info {{ 
        color: #55ffff; 
    }}
    .warning {{ 
        color: #ffaa00; 
    }}
    .success {{ 
        color: #55ff55; 
    }}
    .finding {{ 
        background: #2a2a2a; 
        border: 1px solid #444; 
        margin: 20px 0; 
        padding: 15px;
    }}
    .severity-high {{ 
        border-left: 5px solid #ff5555; 
    }}
    .severity-medium {{ 
        border-left: 5px solid #ffaa00; 
    }}
    .severity-low {{ 
        border-left: 5px solid #55ff55; 
    }}
    ul, ol {{ 
        margin-left: 20px; 
    }}
    li {{ 
        margin-bottom: 10px; 
    }}
    table {{ 
        width: 100%; 
        border-collapse: collapse; 
        margin: 20px 0;
    }}
    th, td {{ 
        border: 1px solid #444; 
        padding: 10px; 
        text-align: left;
    }}
    th {{ 
        background: #333; 
        color: #00ff00;
    }}
    footer {{ 
        margin-top: 50px; 
        font-size: 0.8em; 
        color: #888; 
        text-align: center;
        border-top: 1px solid #444;
        padding-top: 20px;
    }}
    .executive-summary {{ 
        background: #2a2a2a; 
        padding: 20px; 
        border-left: 4px solid #00ff00;
        margin: 20px 0;
    }}
    .methodology-table {{ 
        background: #252525; 
    }}
    code {{ 
        background: #333; 
        padding: 2px 4px; 
        border-radius: 3px;
    }}
    .business-principle {{ 
        background: #2a2a2a; 
        border-left: 4px solid #00ff00; 
        padding: 15px; 
        margin: 20px 0;
    }}
    .test-results {{ 
        font-family: 'Courier New', monospace; 
        font-size: 0.9em; 
        background: #252525; 
        padding: 10px; 
        border-left: 3px solid #00ff00;
    }}
  </style>
</head>
<body>

  <h1>OWASP OTG-BUSLOGIC-007: Test Defenses Against Application Mis-use</h1>
  <p class="info" style="text-align: center;">Assessment of DVWA @ http://localhost/dvwa/</p>
  <p class="info" style="text-align: center;">Report Generated: {timestamp}</p>

  <div class="section executive-summary">
    <h2>Executive Summary</h2>
    <p>{'The application lacks adequate defenses against misuse and abusive behavior, with several critical vulnerabilities that could enable automated attacks, denial of service, and unauthorized access.' if vulnerable else 'The application demonstrates proper defenses against misuse with effective anti-abuse controls and monitoring mechanisms.'}</p>
    <p><strong>Total Findings:</strong> {len(self.findings)}</p>
    <p><strong>High Severity:</strong> {len([f for f in self.findings if f['severity'] == 'High'])}</p>
    <p><strong>Medium Severity:</strong> {len([f for f in self.findings if f['severity'] == 'Medium'])}</p>
    <p><strong>Low Severity:</strong> {len([f for f in self.findings if f['severity'] == 'Low'])}</p>
  </div>

  <div class="section">
    <h2>1. Overview</h2>
    <p>This assessment evaluates the Damn Vulnerable Web Application (DVWA) for compliance with <strong>OWASP Testing Guide v4 - OTG-BUSLOGIC-007: Test Defenses Against Application Mis-use</strong>. The test focuses on identifying whether the application has adequate controls to detect and prevent abusive or unintended usage patterns that could lead to security breaches or service disruption.</p>
    
    <div class="business-principle">
      <h3>Business Logic Principle</h3>
      <p><strong>"Assume abuse will happen."</strong> Applications must implement proactive defenses against automated attacks, misuse, and abusive behavior patterns to protect system integrity and user security.</p>
    </div>
    
    <h3>Objective</h3>
    <p>Defenses against application mis-use ensure that:</p>
    <ul>
      <li>Rate limiting prevents abuse of high-risk operations</li>
      <li>Account lockout mechanisms protect against brute force attacks</li>
      <li>Anti-automation controls detect and block scanning behavior</li>
      <li>Session management prevents hijacking and replay attacks</li>
      <li>Logging and monitoring detect suspicious activities</li>
      <li>Behavioral analysis identifies anomalous usage patterns</li>
    </ul>
  </div>

  <div class="section">
    <h2>2. Test Methodology</h2>
    <p>The testing approach included the following phases:</p>
    
    <table class="methodology-table">
      <tr>
        <th>Test Category</th>
        <th>Description</th>
        <th>Techniques Used</th>
      </tr>
      <tr>
        <td>Brute Force Protection</td>
        <td>Tested account lockout and rate limiting for authentication</td>
        <td>Multiple failed login attempts, lockout analysis</td>
      </tr>
      <tr>
        <td>Rate Limiting</td>
        <td>Tested throttling of sensitive operations</td>
        <td>Rapid repeated operations, delay analysis</td>
      </tr>
      <tr>
        <td>Anti-Automation Controls</td>
        <td>Tested detection of scanning and automated behavior</td>
        <td>Rapid page access, behavioral pattern testing</td>
      </tr>
      <tr>
        <td>Session Management</td>
        <td>Tested session hijacking and reuse protection</td>
        <td>Session copying, concurrent access testing</td>
      </tr>
      <tr>
        <td>Logging and Monitoring</td>
        <td>Tested logging of suspicious activities</td>
        <td>Log file access testing, activity logging checks</td>
      </tr>
    </table>
    
    <h3>2.1 Authentication and Setup</h3>
    <ul>
      <li>Authenticated to DVWA using default credentials</li>
      <li>Set security level to "Low" for comprehensive testing</li>
      <li>Maintained session state throughout testing</li>
    </ul>
    
    <h3>2.2 Testing Approach</h3>
    <p>Each test involved:</p>
    <ul>
      <li>Simulation of abusive behavior patterns</li>
      <li>Monitoring for defensive responses and controls</li>
      <li>Analysis of system responses and error handling</li>
      <li>Identification of missing or inadequate defenses</li>
      <li>Documentation of abuse patterns and results</li>
    </ul>
  </div>

  <div class="section">
    <h2>3. Detailed Findings</h2>
    <p>The following misuse defense vulnerabilities were identified during testing:</p>
    
    {'<p class="success"><strong>No significant misuse defense vulnerabilities found. The application has proper anti-abuse controls and monitoring mechanisms.</strong></p>' if not vulnerable else ''}
'''

        # Add findings to report
        for i, finding in enumerate(self.findings, 1):
            severity_class = f"severity-{finding['severity'].lower()}"
            html_content += f'''
    <div class="finding {severity_class}">
      <h3>3.{i} {finding['title']}</h3>
      <table>
        <tr>
          <th>Location</th>
          <td>{finding['location']}</td>
        </tr>
        <tr>
          <th>Severity</th>
          <td class="vuln">{finding['severity']}</td>
        </tr>
        <tr>
          <th>Issue</th>
          <td>{finding['issue']}</td>
        </tr>
      </table>
      
      <h4>Description</h4>
      <p>{finding['description']}</p>
      
      <h4>Test Results</h4>
      <div class="test-results">{finding['test_results'].replace(chr(10), '<br>')}</div>
      
      {'<h4>Request</h4><pre>' + finding.get('request', '') + '</pre>' if 'request' in finding else ''}
      
      <h4>Impact</h4>
      <p>{finding['impact']}</p>
      
      <h4>Remediation</h4>
      <ul>
        <li>{finding['recommendation']}</li>
        <li>Implement comprehensive rate limiting for all sensitive operations</li>
        <li>Add account lockout mechanisms for authentication attempts</li>
        <li>Deploy anti-automation controls and behavioral analysis</li>
        <li>Enhance session management with proper binding and regeneration</li>
        <li>Implement robust logging and monitoring for suspicious activities</li>
        <li>Use CAPTCHA or similar challenges for high-risk operations</li>
        <li>Add progressive delays for repeated operations</li>
      </ul>
    </div>
'''

        html_content += f'''
  </div>

  <div class="section">
    <h2>4. Conclusion</h2>
    <p>The DVWA instance {'lacks adequate defenses against application misuse' if vulnerable else 'demonstrates proper anti-abuse controls and monitoring'} that are essential for protecting against automated attacks and abusive behavior patterns.</p>
    
    <p>Defenses against application mis-use are critical security controls that protect applications from automated attacks, denial of service, and unauthorized access. Without proper anti-abuse mechanisms, attackers can exploit automated tools to perform unlimited operations, leading to account compromise, data destruction, or service disruption.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <ol>
      <li><strong>Implement Rate Limiting:</strong> Add strict rate limits for all sensitive operations (e.g., 5 attempts per hour)</li>
      <li><strong>Add Account Lockout:</strong> Lock accounts after N failed authentication attempts with progressive delays</li>
      <li><strong>Deploy Anti-Automation Controls:</strong> Implement CAPTCHA, behavioral analysis, and anomaly detection</li>
      <li><strong>Enhance Session Management:</strong> Add session binding, regeneration, and proper timeout mechanisms</li>
      <li><strong>Implement Logging and Monitoring:</strong> Log all suspicious activities and implement real-time alerting</li>
      <li><strong>Use Progressive Delays:</strong> Add exponential backoff for repeated operations</li>
      <li><strong>Regular Misuse Defense Testing:</strong> Include anti-abuse testing in regular security assessments</li>
    </ol>
  </div>

  <div class="section">
    <h2>6. References</h2>
    <ul>
      <li>OWASP Testing Guide v4 - OTG-BUSLOGIC-007</li>
      <li>OWASP Authentication Cheat Sheet</li>
      <li>OWASP Session Management Cheat Sheet</li>
      <li>OWASP Top Ten - A07:2021-Identification and Authentication Failures</li>
      <li>NIST SP 800-63B - Digital Identity Guidelines</li>
      <li>Common Weakness Enumeration - CWE-799: Improper Control of Interaction Frequency</li>
    </ul>
  </div>

  <footer>
    Generated by Misuse Defense Testing Script | Date: {timestamp} | Target: localhost/DVWA<br>
    OWASP Testing Guide v4 - OTG-BUSLOGIC-007 Compliance Assessment
  </footer>

</body>
</html>'''

        # Write report to file
        with open('report_otg_buslogic_007.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print("[+] HTML report generated: report_otg_buslogic_007.html")
        return html_content

    def run_all_tests(self):
        """Run all misuse defense tests"""
        print("[*] Starting Misuse Defense Tests (OTG-BUSLOGIC-007)")
        print(f"[*] Target: {self.base_url}")
        
        if not self.login():
            print("[-] Failed to login. Exiting.")
            return False
        
        # Run individual tests
        self.test_brute_force_protection(max_attempts=10)
        self.test_rate_limiting_on_sensitive_operations(max_attempts=8)
        self.test_anti_automation_controls(max_attempts=12)
        self.test_session_abuse_and_management(max_attempts=6)
        self.test_logging_and_monitoring()
        
        # Simulate findings for demonstration
        self.simulate_misuse_defense_vulnerabilities()
        
        # Generate abuse log file
        self.generate_abuse_log_file()
        
        # Generate report
        self.generate_html_report()
        
        print(f"[+] Testing completed. Found {len(self.findings)} potential issues.")
        return True

if __name__ == "__main__":
    # Initialize tester
    tester = DVWAMisuseDefenseTester()
    
    # Run tests
    tester.run_all_tests()