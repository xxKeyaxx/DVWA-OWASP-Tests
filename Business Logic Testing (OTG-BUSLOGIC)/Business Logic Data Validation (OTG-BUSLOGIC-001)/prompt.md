# AI Coding Agent Prompt: Business Logic Data Validation Test Script for DVWA (OTG-BUSLOGIC-001)

## Objective

Create a Python-based automated testing script that evaluates **business logic data validation** on the **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on localhost**. The script must specifically target **OWASP Testing Guide v4 - OTG-BUSLOGIC-001: Test Business Logic Data Validation**.

After executing the test cases, the agent must generate a professional, **OSCP/OWASP-style HTML report** that documents findings, methodology, vulnerabilities (if any), and recommendations — styled to resemble official penetration testing reports (e.g., OSCP exam reports or OWASP assessment deliverables).

---

## Scope

- Target: DVWA v1.x+ running on `http://localhost/dvwa/`
- Environment: Localhost via XAMPP (Apache + MySQL + PHP)
- Authentication: Script must handle login using default credentials (`admin:password`) or configurable ones.
- Focus: **Business logic data validation flaws**, not just input sanitization or injection.
- Specific Test Area: Identify whether the application validates **logically consistent data** both on client and server side.

> **Note**: This is *not* about SQLi, XSS, or command injection. It's about whether the app accepts data that is *technically syntactically correct* but *logically invalid* in context.

---

## Requirements for the AI Agent

### 1. **Script Functionality**

Develop a **Python script** (`test_otg_buslogic_001.py`) that:

#### a. **Handles Authentication**
- Automatically logs into DVWA using the login form.
- Manages session cookies (use `requests.Session()`).
- Handles security level settings (set to "Low" initially for testing, then optionally test others).

#### b. **Identifies Business Logic Flows**
Target one or more of the following modules in DVWA where business logic validation can be tested:
- **User Registration / Profile Update**
- **Password Change Functionality**
- **Guestbook or Comment Submissions**
- **Security Level Selection (e.g., setting invalid levels like 'Mediumd' or 999)**
- **Any form accepting structured data (e.g., dates, IDs, codes)**

> Example: Attempt to submit a birthdate in the future, or a username already taken, or change password without current password confirmation when logic demands it.

#### c. **Tests for Logical Data Validation**
Perform tests such as:

| Test Case | Description |
|--------|-------------|
| ✅ **Invalid Semantic Values** | Submit data that passes format checks but fails logic (e.g., future birthdate, SSN from invalid range, negative age) |
| ✅ **Missing State Dependencies** | Bypass prerequisite steps (e.g., change password without providing old password) |
| ✅ **Direct Parameter Manipulation** | Modify hidden fields or parameters to pass logically inconsistent data |
| ✅ **Race Conditions or Inconsistencies** | Where applicable, attempt dual submissions creating invalid state |
| ✅ **Server-Side Only Validation Check** | Confirm validation occurs server-side, not just in JavaScript |

#### d. **Logs All Requests/Responses**
- Capture HTTP requests and responses (status codes, headers, bodies).
- Note whether invalid logical data was accepted by the backend.

#### e. **Determines Vulnerability**
Define a vulnerability if:
- The server accepts **logically invalid data**.
- The system allows actions without required preconditions.
- There is **no server-side enforcement** of business rules.

---

### 2. **Generate OSCP/OWASP-Style HTML Report**

After testing, generate a standalone **`report_otg_buslogic_001.html`** file with the following structure and styling:

#### 🔹 Design Requirements
- Clean, monospace font layout (e.g., `Courier New`, `Consolas`)
- Dark theme with green/amber/red color coding (inspired by OSCP templates)
- Use embedded CSS (no external files)
- Include DVWA logo or OWASP icon (base64 encoded SVG optional)

#### 🔹 Report Sections

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>OTG-BUSLOGIC-001 Assessment - DVWA</title>
  <style>
    /* OSCP-inspired styling */
    body { background: #1e1e1e; color: #dcdcdc; font-family: 'Courier New', monospace; padding: 20px; }
    h1, h2, h3 { color: #00ff00; }
    .section { margin-bottom: 30px; }
    pre { background: #2d2d2d; padding: 10px; border-left: 4px solid #ff9900; }
    .vuln { color: #ff0000; font-weight: bold; }
    .info { color: #00ffff; }
    footer { margin-top: 50px; font-size: 0.8em; color: #888; }
  </style>
</head>
<body>

  <h1>OWASP OTG-BUSLOGIC-001: Business Logic Data Validation Test</h1>
  <p class="info">Assessment of DVWA @ http://localhost/dvwa/</p>

  <div class="section">
    <h2>1. Summary</h2>
    <p>The application was tested for proper validation of logically consistent data on both client and server sides. Several test cases were executed to determine whether the backend enforces business rules beyond syntactic checks.</p>
  </div>

  <div class="section">
    <h2>2. Test Methodology</h2>
    <ul>
      <li>Authenticated to DVWA using provided credentials</li>
      <li>Targeted high-risk forms involving user input with logical constraints</li>
      <li>Submitted semantically invalid data (e.g., future dates, impossible values)</li>
      <li>Analyzed server response to determine acceptance or rejection</li>
      <li>Compared front-end vs back-end validation enforcement</li>
    </ul>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <!-- Dynamically insert findings here -->
    <h3>3.1 [Finding Title]</h3>
    <p><strong>Location:</strong> /dvwa/vulnerability/page.php</p>
    <p><strong>Issue:</strong> <span class="vuln">Server accepts logically invalid data without validation</span></p>
    <p><strong>Description:</strong> The system allows submission of a birthdate set in the year 3024, which violates real-world constraints.</p>
    <pre>POST /dvwa/update_profile.php HTTP/1.1
Host: localhost
Cookie: PHPSESSID=abc123...
...
birthdate=3024-01-01</pre>
    <p><strong>Impact:</strong> Could lead to data integrity issues, fraud detection bypass, or downstream processing errors.</p>
    <p><strong>Remediation:</strong> Implement server-side semantic validation using domain-aware logic (e.g., max date = today).</p>
  </div>

  <div class="section">
    <h2>4. Conclusion</h2>
    <p>The DVWA instance {% if vulnerable %}exhibits weaknesses{% else %}properly enforces{% endif %} in business logic data validation. Developers should ensure all data is validated for logical consistency on the server side, regardless of client-side checks.</p>
  </div>

  <footer>
    Generated by AI Security Testing Agent | Date: {{timestamp}} | Target: localhost/DVWA
  </footer>

</body>
</html>