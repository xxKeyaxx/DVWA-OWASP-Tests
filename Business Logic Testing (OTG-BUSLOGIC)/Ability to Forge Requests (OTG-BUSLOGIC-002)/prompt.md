# AI Coding Agent Prompt: Test Ability to Forge Requests (OTG-BUSLOGIC-002) for DVWA

## Objective

Create a Python-based automated testing script that evaluates **the ability to forge requests** on the **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on localhost**. The script must specifically target **OWASP Testing Guide v4 - OTG-BUSLOGIC-002: Test Ability to Forge Requests**, focusing on identifying whether the application is vulnerable to unauthorized or manipulated HTTP requests.

After executing the test cases, the agent must generate a professional, **OSCP/OWASP-style HTML report** that documents findings, methodology, vulnerabilities (if any), and recommendations — styled to resemble official penetration testing reports (e.g., OSCP exam reports or OWASP assessment deliverables).

---

## Scope

- **Target**: DVWA v1.x+ running on `http://localhost/dvwa/`
- **Environment**: Localhost via XAMPP (Apache + MySQL + PHP)
- **Authentication**: Script must handle login using default credentials (`admin:password`) or configurable ones.
- **Focus**: Detecting whether an attacker can **forge or manipulate requests** to perform actions they should not be authorized to do.
- **Test Modules**: Include but are not limited to:
  - Brute Force
  - Command Execution
  - File Inclusion
  - CSRF
  - SQL Injection
  - XSS
  - Auth Bypass

> This test focuses on **business logic flaws related to request integrity**, not just technical injection vulnerabilities.

---

## Requirements for the AI Agent

### 1. **Script Functionality**

Develop a **Python script** (`test_otg_buslogic_002.py`) that:

#### a. **Handles Authentication & Session Management**
- Automatically logs into DVWA using the login form.
- Manages session cookies using `requests.Session()`.
- Handles CSRF tokens (e.g., `user_token`, `session_token`) where required.
- Configurable credentials and target URL.

#### b. **Identifies Request-Based Business Logic Flows**
Target modules where **request forgery** can occur:
- Direct access to privileged pages without authorization
- Parameter tampering (e.g., changing `user_id`, `action`, `level`)
- Missing access controls (IDOR-like behavior)
- Predictable form submissions without anti-CSRF tokens
- Replay attacks or forced browsing

> Example: Can a non-admin user access `/dvwa/admin.php` directly? Can we change `security=high` to `security=impossible` via request manipulation?

#### c. **Tests for Request Forgery Vulnerabilities**
Perform the following types of tests:

| Test Type | Description |
|---------|-------------|
| ✅ **Direct Request Forgery** | Attempt to access restricted pages directly (e.g., `/dvwa/setup.php`) |
| ✅ **Parameter Tampering** | Modify parameters like `id`, `page`, `action`, `security` to escalate privileges |
| ✅ **CSRF Testing** | Verify if sensitive actions (e.g., password change) lack CSRF protection |
| ✅ **Access Control Bypass** | Attempt to access functionality without proper role/permission |
| ✅ **Request Replay** | Replay authenticated requests to verify session integrity |

#### d. **Logs All Requests and Responses**
- Capture full HTTP requests (method, headers, body).
- Log status codes, response content, and observed behavior.
- Identify whether forged requests were **accepted** by the server.

#### e. **Determines Vulnerability**
Define a vulnerability if:
- The server processes a request that should require additional authorization.
- Sensitive actions can be performed without proper validation.
- Parameters can be manipulated to alter application behavior.
- No CSRF protection exists for state-changing operations.

---

### 2. **Generate OSCP/OWASP-Style HTML Report**

After testing, generate a standalone **`report_otg_buslogic_002.html`** file with the following structure and styling:

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
  <title>OTG-BUSLOGIC-002 Assessment - DVWA</title>
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

  <h1>OWASP OTG-BUSLOGIC-002: Test Ability to Forge Requests</h1>
  <p class="info">Assessment of DVWA @ http://localhost/dvwa/</p>

  <div class="section executive-summary">
    <h2>Executive Summary</h2>
    <p>The application was tested for susceptibility to forged HTTP requests. Several endpoints were found to lack proper access control and request validation mechanisms.</p>
    <p><strong>Total Findings:</strong> 3</p>
    <p><strong>High Severity:</strong> 2</p>
    <p><strong>Medium Severity:</strong> 1</p>
  </div>

  <div class="section">
    <h2>1. Overview</h2>
    <p>OTG-BUSLOGIC-002 evaluates whether an attacker can forge or manipulate requests to perform unauthorized actions. Unlike input-based vulnerabilities (e.g., XSS, SQLi), this test focuses on the integrity of the request itself — can a user perform actions they shouldn’t by modifying or replaying requests?</p>
  </div>

  <div class="section">
    <h2>2. Test Methodology</h2>
    <ul>
      <li>Authenticated to DVWA and established valid session</li>
      <li>Identified sensitive endpoints (setup, config, admin, etc.)</li>
      <li>Attempted direct access to restricted pages</li>
      <li>Modified request parameters to escalate privileges</li>
      <li>Tested for CSRF on state-changing operations</li>
      <li>Analyzed server responses for success indicators</li>
    </ul>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    
    <div class="finding">
      <h3>3.1 Direct Access to Setup Page</h3>
      <table>
        <tr><th>Location</th><td>/dvwa/setup.php</td></tr>
        <tr><th>Severity</th><td class="vuln">High</td></tr>
        <tr><th>Issue</th><td>Unauthenticated access to database setup functionality</td></tr>
      </table>
      <h4>Description</h4>
      <p>The setup page is accessible without authentication, allowing an attacker to reinitialize the database.</p>
      <h4>Request</h4>
      <pre>GET /dvwa/setup.php HTTP/1.1
Host: localhost
Connection: close</pre>
      <h4>Impact</h4>
      <p>Complete system compromise via DB reset or reconfiguration.</p>
      <h4>Remediation</h4>
      <p>Implement authentication and authorization checks on all administrative endpoints.</p>
    </div>

  </div>

  <div class="section">
    <h2>4. Conclusion</h2>
    <p>The application {% if vulnerable %}is vulnerable to request forgery attacks{% else %}properly validates and authorizes all requests{% endif %}. Developers should ensure that every request is validated for authenticity, authorization, and intent.</p>
  </div>

  <footer>
    Generated by AI Security Testing Agent | Date: {{timestamp}} | Target: localhost/DVWA
  </footer>

</body>
</html>