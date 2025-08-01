# AI Coding Agent Prompt: Test Upload of Malicious Files (OTG-BUSLOGIC-009)

## Objective

Create a Python-based automated testing script that evaluates **file upload functionality** on the **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on localhost**. The script must specifically target **OWASP Testing Guide v4 - OTG-BUSLOGIC-009: Test Upload of Malicious Files**, focusing on identifying whether the application properly validates and secures file uploads to prevent execution of malicious content.

After executing the test cases, the agent must generate a professional, **OSCP/OWASP-style HTML report** that documents findings, methodology, vulnerabilities (if any), and recommendations — styled to resemble official penetration testing reports (e.g., OSCP exam reports or OWASP assessment deliverables).

---

## Scope

- **Target**: DVWA v1.x+ running on `http://localhost/dvwa/`
- **Environment**: Localhost via XAMPP (Apache + MySQL + PHP)
- **Authentication**: Script must handle login using default credentials (`admin:password`) or configurable ones.
- **Focus**: Detecting whether the application is vulnerable to **malicious file uploads** including:
  - Web shells
  - Script injection
  - MIME type bypass
  - Path traversal
  - Double extension attacks
  - Content-type manipulation
- **Test Module**: `/vulnerabilities/upload/` (DVWA's file upload section)

> This test focuses on **business logic flaws in file upload validation**, not just technical vulnerabilities.

---

## Requirements for the AI Agent

### 1. **Script Functionality**

Develop a **Python script** (`test_otg_buslogic_009.py`) that:

#### a. **Handles Authentication & Session Management**
- Automatically logs into DVWA using the login form.
- Manages session cookies using `requests.Session()`.
- Handles CSRF tokens (e.g., `user_token`, `session_token`) where required.
- Configurable credentials and target URL.

#### b. **Identifies File Upload Vectors**
Target the file upload functionality in DVWA:
- `/vulnerabilities/upload/`
- Analyze upload restrictions (if any)
- Determine allowed file types and size limits

#### c. **Tests for Malicious File Upload Vulnerabilities**
Perform the following types of tests:

| Test Type | Payload Example |
|---------|-----------------|
| ✅ **Web Shell Upload** | `shell.php`, `malicious.php` |
| ✅ **Double Extension** | `shell.php.jpg`, `webshell.pHp` |
| ✅ **MIME Type Spoofing** | Send `image/jpg` for PHP file |
| ✅ **Content-Type Manipulation** | Modify `Content-Type` header |
| ✅ **Path Traversal** | `../../malicious.php` |
| ✅ **Hidden Double Extensions** | `shell.php%00.jpg` |
| ✅ **Case Manipulation** | `SHELL.PHP`, `shell.PhP` |
| ✅ **JavaScript Payloads** | `xss.html`, `malicious.svg` |

#### d. **Verifies Upload Success and Execution**
- Check if upload was successful (200 OK)
- Verify if file is accessible via direct URL
- Test if uploaded PHP file executes code
- Attempt to run commands through web shell
- Log all request/response pairs

#### e. **Determines Vulnerability**
Define a vulnerability if:
- Malicious files (e.g., `.php`) are accepted
- Uploaded files are accessible via web
- Server executes uploaded scripts
- No proper file type validation is enforced
- MIME type or extension checks can be bypassed

---

### 2. **Generate OSCP/OWASP-Style HTML Report**

After testing, generate a standalone **`report_otg_buslogic_009.html`** file with the following structure and styling:

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
  <title>OTG-BUSLOGIC-009 Assessment - DVWA</title>
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

  <h1>OWASP OTG-BUSLOGIC-009: Test Upload of Malicious Files</h1>
  <p class="info">Assessment of DVWA @ http://localhost/dvwa/</p>

  <div class="section executive-summary">
    <h2>Executive Summary</h2>
    <p>The application was tested for proper validation of file uploads. Several malicious file types were successfully uploaded and executed, indicating inadequate file upload controls.</p>
    <p><strong>Total Findings:</strong> 3</p>
    <p><strong>High Severity:</strong> 3</p>
    <p><strong>Medium Severity:</strong> 0</p>
  </div>

  <div class="section">
    <h2>1. Overview</h2>
    <p>OTG-BUSLOGIC-009 evaluates whether the application properly validates file uploads to prevent malicious files from being uploaded and executed. It tests if the system enforces proper file type restrictions, content validation, and execution controls.</p>
  </div>

  <div class="section">
    <h2>2. Test Methodology</h2>
    <ul>
      <li>Authenticated to DVWA and established valid session</li>
      <li>Identified file upload functionality</li>
      <li>Prepared malicious file payloads</li>
      <li>Tested various upload bypass techniques</li>
      <li>Verified upload success and execution capability</li>
      <li>Analyzed server responses and file accessibility</li>
    </ul>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    
    <div class="finding">
      <h3>3.1 Arbitrary PHP File Upload</h3>
      <table>
        <tr><th>Location</th><td>/dvwa/vulnerabilities/upload/</td></tr>
        <tr><th>Severity</th><td class="vuln">High</td></tr>
        <tr><th>Issue</th><td>Application allows upload of executable PHP files</td></tr>
      </table>
      <h4>Description</h4>
      <p>The file upload functionality allows PHP files to be uploaded without proper validation, enabling remote code execution.</p>
      <h4>Payload</h4>
      <pre><?php system($_GET['cmd']); ?></pre>
      <h4>Upload Path</h4>
      <p>http://localhost/dvwa/hackable/uploads/shell.php</p>
      <h4>Verification</h4>
      <pre>GET http://localhost/dvwa/hackable/uploads/shell.php?cmd=whoami</pre>
      <h4>Impact</h4>
      <p>Full remote code execution on the server, leading to complete system compromise.</p>
      <h4>Remediation</h4>
      <p>Implement strict file type validation, use allowlists, disable execution in upload directories, and scan uploaded files.</p>
    </div>

  </div>

  <div class="section">
    <h2>4. Conclusion</h2>
    <p>The application {% if vulnerable %}is vulnerable to malicious file uploads{% else %}properly validates and secures file uploads{% endif %}. Developers must ensure that uploaded files cannot be used to execute arbitrary code on the server.</p>
  </div>

  <footer>
    Generated by AI Security Testing Agent | Date: {{timestamp}} | Target: localhost/DVWA
  </footer>

</body>
</html>