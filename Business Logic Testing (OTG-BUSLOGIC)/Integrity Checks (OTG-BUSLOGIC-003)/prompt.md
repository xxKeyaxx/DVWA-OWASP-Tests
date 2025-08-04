# AI Coding Agent Prompt: Test Integrity Checks (OTG-BUSLOGIC-003) for DVWA

## Objective

Create a Python-based automated testing script that evaluates **data and process integrity controls** on the **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on localhost**. The script must specifically target **OWASP Testing Guide v4 - OTG-BUSLOGIC-003: Test Integrity Checks**, focusing on identifying whether the application properly validates critical data and workflow states server-side, and prevents tampering through client-side manipulation.

After executing the test cases, the agent must generate a professional, **OSCP/OWASP-style HTML report** that documents findings, methodology, vulnerabilities (if any), and recommendations — styled to resemble official penetration testing reports (e.g., OSCP exam reports or OWASP assessment deliverables).

---

## Scope

- **Target**: DVWA v1.x+ running on `http://localhost/dvwa/`
- **Environment**: Localhost via XAMPP (Apache + MySQL + PHP)
- **Authentication**: Script must handle login using default credentials (`admin:password`) or configurable ones.
- **Focus**: Detecting **integrity violations** where:
  - Hidden or non-editable fields are trusted without server validation.
  - Business workflow steps can be bypassed.
  - Client-side only validation is relied upon.
  - Unauthorized users can manipulate data they should not control.
- **Test Modules**: Include but are not limited to:
  - CSRF (password change)
  - Command Execution
  - SQL Injection
  - Security Level Selection
  - Any form with hidden fields or read-only values

> This test focuses on **business logic integrity**, not just input sanitization or injection flaws.

---

## Requirements for the AI Agent

### 1. **Script Functionality**

Develop a **Python script** (`test_otg_buslogic_003.py`) that:

#### a. **Handles Authentication & Session Management**
- Automatically logs into DVWA using the login form.
- Manages session cookies using `requests.Session()`.
- Handles CSRF tokens (e.g., `user_token`, `session_token`) where required.
- Configurable credentials and target URL.

#### b. **Identifies Integrity-Critical Components**
Target areas where **data integrity** should be enforced:
- Hidden form fields (e.g., `user_id`, `role`, `price`)
- Read-only or disabled UI elements
- Workflow state indicators (e.g., `step=1`, `status=draft`)
- Client-side validated inputs (e.g., password match via JavaScript)

> Example: Can a user change their `user_id` or bypass password confirmation logic?

#### c. **Tests for Integrity Check Bypasses**
Perform the following types of tests:

| Test Type | Description |
|---------|-------------|
| ✅ **Hidden Field Tampering** | Modify hidden fields like `user_id`, `role`, or `token` and observe server response |
| ✅ **Client-Side Validation Bypass** | Disable JS and submit invalid data (e.g., mismatched passwords) |
| ✅ **Workflow Step Skipping** | Attempt to jump to final step without completing prerequisites |
| ✅ **Parameter Injection** | Add unauthorized parameters (e.g., `admin=1`) to requests |
| ✅ **State Manipulation** | Change values like `security=impossible` when not allowed |

#### d. **Logs All Requests and Responses**
- Capture full HTTP requests (method, headers, body).
- Log status codes, response content, and observed behavior.
- Identify whether tampered data was **accepted** by the server.

#### e. **Determines Vulnerability**
Define a vulnerability if:
- The server processes **tampered hidden fields** without validation.
- Actions succeed despite **bypassing client-side checks**.
- Users can **manipulate data or state** they should not control.
- No server-side confirmation of logically critical values (e.g., password match).

---

### 2. **Generate OSCP/OWASP-Style HTML Report**

After testing, generate a standalone **`report_otg_buslogic_003.html`** file with the following structure and styling:

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
  <title>OTG-BUSLOGIC-003 Assessment - DVWA</title>
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

  <h1>OWASP OTG-BUSLOGIC-003: Test Integrity Checks</h1>
  <p class="info">Assessment of DVWA @ http://localhost/dvwa/</p>

  <div class="section executive-summary">
    <h2>Executive Summary</h2>
    <p>The application was tested for proper enforcement of data and process integrity. Several instances were found where client-side only validation was relied upon, allowing potential tampering of hidden fields and workflow states.</p>
    <p><strong>Total Findings:</strong> 3</p>
    <p><strong>High Severity:</strong> 2</p>
    <p><strong>Medium Severity:</strong> 1</p>
  </div>

  <div class="section">
    <h2>1. Overview</h2>
    <p>OTG-BUSLOGIC-003 evaluates whether the application enforces integrity of data and business processes. It tests if the server validates all critical operations server-side and prevents manipulation of hidden fields, non-editable data, or workflow states.</p>
  </div>

  <div class="section">
    <h2>2. Test Methodology</h2>
    <ul>
      <li>Authenticated to DVWA and established valid session</li>
      <li>Identified forms with hidden fields, read-only data, or client-side validation</li>
      <li>Intercepted and modified requests to tamper with hidden parameters</li>
      <li>Bypassed JavaScript validation to submit logically invalid data</li>
      <li>Attempted to skip workflow steps or inject unauthorized parameters</li>
      <li>Analyzed server responses for success indicators</li>
    </ul>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    
    <div class="finding">
      <h3>3.1 Missing Server-Side Password Confirmation Check</h3>
      <table>
        <tr><th>Location</th><td>/dvwa/vulnerabilities/csrf/</td></tr>
        <tr><th>Severity</th><td class="vuln">High</td></tr>
        <tr><th>Issue</th><td>Server accepts different 'password_new' and 'password_conf' values</td></tr>
      </table>
      <h4>Description</h4>
      <p>The application relies solely on client-side JavaScript to ensure password fields match. When bypassed, the server processes mismatched passwords.</p>
      <h4>Request</h4>
      <pre>POST /dvwa/vulnerabilities/csrf/ HTTP/1.1
Host: localhost
Cookie: PHPSESSID=abc123...

password_new=hacked&password_conf=original&Change=Change</pre>
      <h4>Impact</h4>
      <p>Could allow attackers to set a password different from what was confirmed.</p>
      <h4>Remediation</h4>
      <p>Always compare both password fields on the server side before processing.</p>
    </div>

  </div>

  <div class="section">
    <h2>4. Conclusion</h2>
    <p>The application {% if vulnerable %}fails to enforce proper integrity checks{% else %}properly validates all critical data server-side{% endif %}. Developers must ensure that no business-critical decision is based on client-supplied data without server-side verification.</p>
  </div>

  <footer>
    Generated by AI Security Testing Agent | Date: {{timestamp}} | Target: localhost/DVWA
  </footer>

</body>
</html>