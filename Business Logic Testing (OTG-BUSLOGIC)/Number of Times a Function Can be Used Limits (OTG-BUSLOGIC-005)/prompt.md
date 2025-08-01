# AI Coding Agent Prompt: Test Number of Times a Function Can Be Used Limits (OTG-BUSLOGIC-005)

## Objective

Create a Python-based automated testing script that evaluates **usage limits of functions and operations** on the **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on localhost**. The script must specifically target **OWASP Testing Guide v4 - OTG-BUSLOGIC-005: Test Number of Times a Function Can be Used Limits**, focusing on identifying whether the application enforces proper restrictions on how often a user can perform certain actions.

After executing the test cases, the agent must generate a professional, **OSCP/OWASP-style HTML report** that documents findings, methodology, vulnerabilities (if any), and recommendations — styled to resemble official penetration testing reports (e.g., OSCP exam reports or OWASP assessment deliverables).

---

## Scope

- **Target**: DVWA v1.x+ running on `http://localhost/dvwa/`
- **Environment**: Localhost via XAMPP (Apache + MySQL + PHP)
- **Authentication**: Script must handle login using default credentials (`admin:password`) or configurable ones.
- **Focus**: Detecting whether the application enforces **usage limits** on:
  - Authentication attempts
  - Password changes
  - Security level changes
  - Form submissions
  - Sensitive operations (e.g., database setup)
  - Any function that should have rate limiting or usage caps
- **Test Modules**: Include but are not limited to:
  - Brute Force (login attempts)
  - CSRF (password change)
  - Command Execution
  - SQL Injection
  - Setup/Reset functionality
  - Security Level Selection

> This test focuses on **business logic limits**, not just technical vulnerabilities.

---

## Requirements for the AI Agent

### 1. **Script Functionality**

Develop a **Python script** (`test_otg_buslogic_005.py`) that:

#### a. **Handles Authentication & Session Management**
- Automatically logs into DVWA using the login form.
- Manages session cookies using `requests.Session()`.
- Handles CSRF tokens (e.g., `user_token`, `session_token`) where required.
- Configurable credentials and target URL.

#### b. **Identifies Functions with Usage Limits**
Target operations that **should have usage restrictions**:
- Login attempts (brute force protection)
- Password change frequency
- Database setup/reset operations
- Security level changes
- Repeated form submissions
- Sensitive administrative actions

> Example: Can a user reset the database 100 times? Can they change password repeatedly?

#### c. **Tests for Usage Limit Bypasses**
Perform the following types of tests:

| Test Type | Description |
|---------|-------------|
| ✅ **Repeated Login Attempts** | Try multiple failed logins to test account lockout |
| ✅ **Password Change Flooding** | Change password repeatedly without delay |
| ✅ **Database Reset Abuse** | Attempt to reset database multiple times |
| ✅ **Security Level Cycling** | Rapidly change security levels |
| ✅ **Form Resubmission** | Submit same form multiple times (replay) |
| ✅ **Session Reuse After Logout** | Test if old session remains valid |

#### d. **Logs All Requests and Responses**
- Capture full HTTP requests (method, headers, body).
- Log status codes, response content, and observed behavior.
- Track number of successful vs failed attempts.
- Identify whether usage limits were enforced.

#### e. **Determines Vulnerability**
Define a vulnerability if:
- A function can be used **unlimited times** without restriction.
- No rate limiting or throttling is in place.
- Critical operations lack **anti-automation** or **anti-abuse** controls.
- Actions can be **replayed** without consequence.

---

### 2. **Generate OSCP/OWASP-Style HTML Report**

After testing, generate a standalone **`report_otg_buslogic_005.html`** file with the following structure and styling:

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
  <title>OTG-BUSLOGIC-005 Assessment - DVWA</title>
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
  </style>
</head>
<body>

  <h1>OWASP OTG-BUSLOGIC-005: Test Function Usage Limits</h1>
  <p class="info">Assessment of DVWA @ http://localhost/dvwa/</p>

  <div class="section executive-summary">
    <h2>Executive Summary</h2>
    <p>The application was tested for proper enforcement of function usage limits. Several operations were found to lack rate limiting or anti-abuse controls, allowing unlimited use of sensitive functions.</p>
    <p><strong>Total Findings:</strong> 3</p>
    <p><strong>High Severity:</strong> 2</p>
    <p><strong>Medium Severity:</strong> 1</p>
  </div>

  <div class="section">
    <h2>1. Overview</h2>
    <p>OTG-BUSLOGIC-005 evaluates whether the application enforces limits on how many times a function can be used. It tests if the system prevents abuse of operations like login, password change, or database reset through rate limiting, throttling, or lockout mechanisms.</p>
  </div>

  <div class="section">
    <h2>2. Test Methodology</h2>
    <ul>
      <li>Authenticated to DVWA and established valid session</li>
      <li>Identified functions that should have usage limits</li>
      <li>Performed repeated executions of sensitive operations</li>
      <li>Measured system response and enforcement of limits</li>
      <li>Tested for replay attacks and session reuse</li>
      <li>Analyzed server responses for success indicators</li>
    </ul>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    
    <div class="finding">
      <h3>3.1 Unlimited Database Reset Functionality</h3>
      <table>
        <tr><th>Location</th><td>/dvwa/setup.php</td></tr>
        <tr><th>Severity</th><td class="vuln">High</td></tr>
        <tr><th>Issue</th><td>Database can be reset unlimited times without restriction</td></tr>
      </table>
      <h4>Description</h4>
      <p>The database setup/reset functionality can be executed repeatedly without any rate limiting, lockout, or confirmation mechanism.</p>
      <h4>Test Results</h4>
      <pre>Attempt 1: Success (200 OK)
Attempt 2: Success (200 OK)
Attempt 10: Success (200 OK)</pre>
      <h4>Impact</h4>
      <p>Could allow denial of service by repeatedly resetting the database and destroying application data.</p>
      <h4>Remediation</h4>
      <p>Implement usage limits, require administrative privileges, and add confirmation steps for destructive operations.</p>
    </div>

  </div>

  <div class="section">
    <h2>4. Conclusion</h2>
    <p>The application {% if vulnerable %}fails to enforce proper usage limits on critical functions{% else %}properly restricts repeated use of sensitive operations{% endif %}. Developers must ensure that all high-risk functions have appropriate rate limiting and anti-abuse controls.</p>
  </div>

  <footer>
    Generated by AI Security Testing Agent | Date: {{timestamp}} | Target: localhost/DVWA
  </footer>

</body>
</html>