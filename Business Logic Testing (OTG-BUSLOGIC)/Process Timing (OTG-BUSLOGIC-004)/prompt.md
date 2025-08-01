# AI Coding Agent Prompt: Test Process Timing (OTG-BUSLOGIC-004) for DVWA

## Objective

Create a Python-based automated testing script that evaluates **process timing vulnerabilities** on the **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on localhost**. The script must specifically target **OWASP Testing Guide v4 - OTG-BUSLOGIC-004: Test Process Timing**, focusing on identifying whether the application is vulnerable to timing-based attacks that could reveal sensitive information or allow unauthorized operations.

After executing the test cases, the agent must generate a professional, **OSCP/OWASP-style HTML report** that documents findings, methodology, vulnerabilities (if any), and recommendations — styled to resemble official penetration testing reports (e.g., OSCP exam reports or OWASP assessment deliverables).

---

## Scope

- **Target**: DVWA v1.x+ running on `http://localhost/dvwa/`
- **Environment**: Localhost via XAMPP (Apache + MySQL + PHP)
- **Authentication**: Script must handle login using default credentials (`admin:password`) or configurable ones.
- **Focus**: Detecting **timing-based vulnerabilities** where:
  - Different response times reveal information about internal processes
  - Operations take predictable time based on input or state
  - Timing can be used to infer valid vs invalid data
  - Race conditions exist in critical operations
- **Test Modules**: Include but are not limited to:
  - Brute Force (user enumeration, password guessing)
  - Command Execution (timing-based command injection)
  - SQL Injection (time-based blind SQLi)
  - File Inclusion (timing variations)
  - Security Level Changes
  - Any operation with variable response times

> This test focuses on **timing-based information disclosure** and **race condition vulnerabilities** in business processes.

---

## Requirements for the AI Agent

### 1. **Script Functionality**

Develop a **Python script** (`test_otg_buslogic_004.py`) that:

#### a. **Handles Authentication & Session Management**
- Automatically logs into DVWA using the login form.
- Manages session cookies using `requests.Session()`.
- Handles CSRF tokens (e.g., `user_token`, `session_token`) where required.
- Configurable credentials and target URL.

#### b. **Identifies Timing-Sensitive Operations**
Target areas where **response timing** might reveal information:
- Authentication endpoints (user enumeration, password guessing)
- Database queries (time-based SQL injection)
- System commands (timing-based command execution)
- File operations (inclusion, upload processing)
- Security state changes (level transitions)
- Multi-step processes with timing dependencies

> Example: Does failed login take different time than successful login? Does valid user check take longer?

#### c. **Tests for Process Timing Vulnerabilities**
Perform the following types of tests:

| Test Type | Description |
|---------|-------------|
| ✅ **Timing-Based User Enumeration** | Measure response times for valid vs invalid usernames |
| ✅ **Time-Based SQL Injection** | Test for blind SQLi using timing delays |
| ✅ **Command Execution Timing** | Inject timing commands to detect command injection |
| ✅ **Race Condition Testing** | Attempt to exploit timing windows in critical operations |
| ✅ **Response Time Analysis** | Compare response times for different inputs or states |
| ✅ **Security Level Timing** | Measure time taken for security level transitions |

#### d. **Measures and Analyzes Response Times**
- Record precise timing for each request (use `time.time()` or similar)
- Compare response times between different inputs
- Identify statistically significant timing differences (>100ms difference)
- Log timing data for analysis and reporting
- Handle network latency variations in measurements

#### e. **Determines Vulnerability**
Define a vulnerability if:
- Response times vary significantly based on input validity
- Timing can be used to infer internal state or data
- Race conditions exist in critical business operations
- Time-based attacks can extract information
- Operations are predictable based on timing patterns

---

### 2. **Generate OSCP/OWASP-Style HTML Report**

After testing, generate a standalone **`report_otg_buslogic_004.html`** file with the following structure and styling:

#### 🔹 Design Requirements
- Clean, monospace font layout (e.g., `Courier New`, `Consolas`)
- Dark theme with green/amber/red color coding (inspired by OSCP templates)
- Use embedded CSS (no external files)
- Include OWASP logo or DVWA icon (base64 encoded SVG optional)
- Fully self-contained HTML

#### 🔹 Report Sections

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>OTG-BUSLOGIC-004 Assessment - DVWA</title>
  <style>
    /* OSCP-inspired styling */
    body { background: #1e1e1e; color: #dcdcdc; font-family: 'Courier New', monospace; padding: 20px; }
    h1, h2, h3 { color: #00ff00; border-bottom: 1px solid #00ff00; }
    .section { margin-bottom: 30px; }
    pre { background: #2d2d2d; padding: 10px; border-left: 4px solid #ff9900; overflow-x: auto; }
    .vuln { color: #ff0000; font-weight: bold; }
    .info { color: #00ffff; }
    .warning { color: #ffaa00; }
    .success { color: #55ff55; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th, td { border: 1px solid #444; padding: 10px; text-align: left; }
    th { background: #333; color: #00ff00; }
    footer { margin-top: 50px; font-size: 0.8em; color: #888; text-align: center; }
    .finding { background: #2a2a2a; padding: 15px; margin: 20px 0; border-left: 5px solid #ff5555; }
    .executive-summary { background: #2a2a2a; padding: 20px; border-left: 4px solid #00ff00; }
    .timing-data { font-family: monospace; font-size: 0.9em; }
  </style>
</head>
<body>

  <h1>OWASP OTG-BUSLOGIC-004: Test Process Timing</h1>
  <p class="info">Assessment of DVWA @ http://localhost/dvwa/</p>

  <div class="section executive-summary">
    <h2>Executive Summary</h2>
    <p>The application was tested for timing-based vulnerabilities that could reveal sensitive information or allow unauthorized operations through response time analysis.</p>
    <p><strong>Total Findings:</strong> 2</p>
    <p><strong>High Severity:</strong> 1</p>
    <p><strong>Medium Severity:</strong> 1</p>
  </div>

  <div class="section">
    <h2>1. Overview</h2>
    <p>OTG-BUSLOGIC-004 evaluates whether the application is vulnerable to timing-based attacks that can reveal information about internal processes, user existence, or database structure through response time analysis.</p>
  </div>

  <div class="section">
    <h2>2. Test Methodology</h2>
    <ul>
      <li>Authenticated to DVWA and established valid session</li>
      <li>Identified timing-sensitive operations and endpoints</li>
      <li>Measured response times for different inputs and states</li>
      <li>Analyzed timing variations for information disclosure</li>
      <li>Tested for race conditions in critical operations</li>
      <li>Performed time-based injection testing</li>
    </ul>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    
    <div class="finding">
      <h3>3.1 Timing-Based User Enumeration</h3>
      <table>
        <tr><th>Location</th><td>/dvwa/vulnerabilities/brute/</td></tr>
        <tr><th>Severity</th><td class="vuln">High</td></tr>
        <tr><th>Issue</th><td>Response time reveals valid vs invalid usernames</td></tr>
      </table>
      <h4>Description</h4>
      <p>The authentication endpoint responds with significantly different timing for valid versus invalid usernames, allowing attackers to enumerate valid user accounts.</p>
      <h4>Timing Data</h4>
      <pre class="timing-data">Valid user 'admin': 0.45s average
Invalid user 'nonexistent': 0.12s average
Timing difference: 330ms</pre>
      <h4>Impact</h4>
      <p>Could allow attackers to enumerate valid usernames for targeted attacks.</p>
      <h4>Remediation</h4>
      <p>Implement consistent response times regardless of user existence. Use rate limiting and account lockout mechanisms.</p>
    </div>

  </div>

  <div class="section">
    <h2>4. Conclusion</h2>
    <p>The application {% if vulnerable %}exhibits timing-based vulnerabilities{% else %}properly handles process timing{% endif %} that could be exploited for information disclosure or unauthorized operations.</p>
  </div>

  <footer>
    Generated by AI Security Testing Agent | Date: {{timestamp}} | Target: localhost/DVWA
  </footer>

</body>
</html>