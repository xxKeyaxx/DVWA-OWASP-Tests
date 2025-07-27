# AI Coding Agent Prompt: SSI Injection Testing Script for DVWA (OTG-INPVAL-009)

## 📌 Overview
Create a Python-based automated testing script that identifies and validates **Server-Side Includes (SSI) Injection vulnerabilities** (aligned with **OWASP OTG-INPVAL-009**) on **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on `localhost`**. Upon completion, the script must generate a **professional, well-designed HTML report** in the style of **OWASP** and **OSCP penetration testing reports**.

---

## 🎯 Target Environment
- **Application**: DVWA (Damn Vulnerable Web Application)
- **Deployment**: XAMPP on `localhost`
- **URL**: `http://localhost/dvwa/`
- **Test Modules**:
  - Command Execution (`/dvwa/vulnerabilities/exec/`)
  - File Inclusion (if available)
  - Any input field that processes user input in a way that might be processed by the web server
- **Authentication Required**: Yes (script must handle login and session)
- **Security Level**: Low (assumed for testing)
- **Prerequisites**: Web server must support SSI (Apache with `.shtml` support enabled)

---

## 🛠️ Script Requirements

### 1. **Core Functionality**
- **Authentication Automation**:
  - Log in to DVWA using provided credentials (e.g., `admin:password`).
  - Handle CSRF tokens (`user_token`) and maintain session cookies.
- **SSI Injection Testing**:
  - Identify input fields that may be vulnerable to SSI injection (especially those that might be processed by the web server).
  - Test with a comprehensive set of SSI payloads:
    - **Command Execution**: `<!--#exec cmd="whoami"-->`
    - **File Inclusion**: `<!--#include file="filename"-->`, `<!--#include virtual="/path/to/file"-->`
    - **Echo with Variables**: `<!--#echo var="DOCUMENT_NAME"-->`, `<!--#echo var="REMOTE_ADDR"-->`
    - **Flagger**: `<!--#config timefmt="%D %E %t SSI-INJECTION-DETECTED %t %D %E"-->`
    - **Date Injection**: `<!--#config timefmt="%A %B %d, %Y %H:%M:%S"--> <!--#echo var="DATE_LOCAL"-->`
  - Test payloads in various input contexts:
    - Text fields
    - URL parameters
    - Headers (if possible)
- **Vulnerability Detection**:
  - Flag inputs that:
    - Execute server-side commands
    - Include file contents in response
    - Return server-side variable values
    - Process SSI directives in any way
  - Use time-based detection for blind SSI injection
  - Verify results by checking for:
    - Command output in response
    - File contents in response
    - Server variables in response
    - Response timing anomalies
- **Session Handling**:
  - Maintain authenticated session throughout the test.
  - Re-authenticate if session expires.

### 2. **Reporting**
- Generate a **single, self-contained HTML report** (`ssi_injection_report.html`) with:
  - **Title**: "SSI Injection Assessment – DVWA (OTG-INPVAL-009)"
  - **Executive Summary**: Brief overview of findings and risk.
  - **Test Details**:
    - Target URL
    - Vulnerability Type: SSI Injection
    - OWASP Test ID: OTG-INPVAL-009
    - Risk Level: High
    - Date & Time of Test
  - **Methodology**:
    - Steps taken (login → input discovery → SSI testing → analysis)
    - Tools used (script name, Python modules)
  - **Findings**:
    - Table of tested inputs and payloads
    - For each vulnerable input:
      - Input field name
      - SSI payload used
      - Response evidence
      - Impact (e.g., command execution, file read)
    - Proof of Concept (PoC) code
    - Screenshots (if using Selenium for verification)
  - **Remediation Recommendations**:
    - Disable SSI if not required
    - Input validation and sanitization
    - Principle of least privilege
    - Web server configuration
  - **References**:
    - OWASP Testing Guide: OTG-INPVAL-009
    - CWE-97: SSI Injection
    - OWASP SSI Injection Cheat Sheet

### 3. **HTML Report Design**
- **Style**: Clean, professional, OSCP/OWASP-like
- **Colors**: Dark blue, white, gray (security-themed)
- **Fonts**: Monospace for code, sans-serif for body
- **Structure**:
  - Header with logo (optional placeholder)
  - Navigation sidebar or sections
  - Collapsible technical details
  - Responsive layout
- Include embedded CSS (no external files)
- Ensure **all HTML output is properly escaped** to prevent rendering issues

### 4. **Technical Specifications**
- **Language**: Python 3.7+
- **Libraries**:
  - `requests` – for HTTP handling
  - `BeautifulSoup4` – for parsing HTML
  - `argparse` – for CLI arguments
  - `datetime`, `os`, `json`, `time` – for logging and data
- **Command-Line Arguments**:
  - `--url`: Target URL (default: `http://localhost/dvwa`)
  - `--username`: DVWA username (default: `admin`)
  - `--password`: DVWA password (default: `password`)
  - `--output`: Output report path (default: `reports/ssi_report.html`)
  - `--timeout`: Request timeout (default: 10 seconds)
  - `--delay`: Delay between requests (default: 1 second)
- **Logging**:
  - Print progress to console
  - Save raw responses for debugging (optional)

---

## 🧾 Expected Output
- A Python script: `dvwa_ssi_injection.py`
- Generated HTML report: `ssi_injection_report.html` (or as specified)
- Report includes:
  - ✅ Vulnerability confirmed
  - ✅ Inputs tested
  - ✅ Payloads used
  - ✅ Risk assessment
  - ✅ Remediation advice
  - ✅ Professional presentation

---

## 📝 Example Usage
```bash
python dvwa_ssi_injection.py \
  --url http://localhost/dvwa \
  --username admin \
  --password password \
  --output reports/ssi_injection_$(date +%F).html