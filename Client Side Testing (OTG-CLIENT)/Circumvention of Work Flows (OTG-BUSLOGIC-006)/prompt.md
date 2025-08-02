# AI Coding Agent Prompt: Circumvention of Work Flows (OTG-BUSLOGIC-006) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that automates testing for **Circumvention of Work Flows (OTG-BUSLOGIC-006)** on a local instance of **Damn Vulnerable Web Application (DVWA)** running via **XAMPP on localhost**. The script must detect and demonstrate business logic flaws where an attacker can bypass intended application workflows (e.g., skip steps, escalate privileges, or manipulate multi-stage processes) and generate a professional, well-structured **OWASP/OSCP-style HTML report** styled to resemble official penetration testing reports.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Set to **Low** (automatically configure via script if possible)
- Test relevant modules: Any multi-step or state-dependent functionality in DVWA

### 2. **Testing Objective: OTG-BUSLOGIC-006 – Circumvention of Work Flows**
- Identify **business logic vulnerabilities** where the intended workflow can be bypassed
- Focus on **workflow bypass** scenarios such as:
  - Skipping prerequisite steps (e.g., accessing high-security functions without proper authorization)
  - Manipulating URL parameters or hidden fields to escalate privileges
  - Repeating or reordering steps to achieve unintended outcomes
  - Bypassing input validation by directly calling backend endpoints
- Although DVWA does not have a complex multi-step workflow, test for **privilege escalation via direct access** to high-security pages or functions
- Example test case:
  - User should only access high security after authentication and proper level setting
  - Test if user can directly access high-security modules (e.g., `vulnerabilities/csrf/`) without going through intended flow

### 3. **Automation Requirements**
- Use `selenium` for browser automation to simulate real user behavior
- Use `requests` and `BeautifulSoup` for session handling and form parsing
- Automate login to DVWA
- Set security level to **Low** initially, then attempt to **manipulate it directly via requests** (bypassing UI)
- Attempt to **skip steps** such as:
  - Accessing high-security pages without changing security level via UI
  - Submitting forms with elevated privileges by modifying hidden inputs
  - Replaying requests to repeat actions (e.g., password reset abuse)
- Log all HTTP responses, status codes, and access outcomes
- Handle CSRF tokens (`user_token`) and session cookies correctly
- Detect if the application enforces workflow state on the server side

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-BUSLOGIC-006_Report.html` file with the following structure and styling:

#### Report Structure
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>OSCP-Style Security Assessment Report</title>
  <style>
    /* OSCP-inspired styling: monospace, dark theme, clean layout */
    body { 
      font-family: 'Courier New', monospace; 
      background: #111; 
      color: #00FF00; 
      padding: 20px; 
      line-height: 1.6;
    }
    .header { text-align: center; margin-bottom: 30px; }
    h1, h2, h3 { color: #00CCFF; border-bottom: 1px solid #00CCFF; padding-bottom: 5px; }
    .section { margin: 20px 0; }
    pre { 
      background: #222; 
      padding: 12px; 
      border-left: 5px solid #00CCFF; 
      overflow-x: auto; 
      font-size: 0.9em;
      color: #FFCC00;
    }
    .evidence { color: #FFCC00; font-weight: bold; }
    .recommendation { color: #AAFF00; }
    .vulnerable { color: #FF5555; font-weight: bold; }
    .safe { color: #55FF55; }
    footer { margin-top: 60px; font-size: 0.8em; text-align: center; color: #666; }
    code { background: #333; padding: 2px 4px; border-radius: 3px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Test ID:</strong> OTG-BUSLOGIC-006</p>
    <p><strong>Vulnerability:</strong> Circumvention of Work Flows</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify if business workflows can be circumvented by skipping steps or manipulating state.</p>
    <p><strong>OWASP Reference:</strong> OTG-BUSLOGIC-006</p>
    <p><strong>Description:</strong> Workflow circumvention occurs when an application fails to enforce proper sequencing or state validation, allowing attackers to bypass intended processes.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Attempt to access high-security modules without changing security level via UI.</p>
    <p>3. Modify hidden form fields (e.g., <code>security</code> level) in requests.</p>
    <p>4. Replay or reorder actions to test for improper state validation.</p>
    <p>5. Analyze server responses for access control enforcement.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Workflow Bypass via Direct Access</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Tested Action:</strong> Accessing CSRF module with high security level enforced</p>
    <p><strong>Method:</strong> Direct URL access and parameter manipulation</p>
    <pre>[Request: POST /security.php with security=high]
[Response: Success, security level changed without UI interaction]</pre>
    <p class="evidence"><strong>Evidence:</strong> Security level changed without following UI workflow.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can bypass intended application workflows, escalate privileges, or perform unauthorized actions by manipulating requests or skipping validation steps. This undermines the application's business logic and access controls.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Enforce workflow state on the server side, not just client/UI.</p>
    <p class="recommendation">- Validate all steps in multi-stage processes before allowing progression.</p>
    <p class="recommendation">- Use server-side session flags to track workflow progress.</p>
    <p class="recommendation">- Implement proper access controls for all endpoints.</p>
    <p class="recommendation">- Log and monitor attempts to bypass workflow steps.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>