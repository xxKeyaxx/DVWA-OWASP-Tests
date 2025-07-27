# AI Coding Agent Prompt: Command Injection Testing Script for DVWA (OTG-INPVAL-013)

## 📌 Overview
Create a Python-based automated testing script that identifies and validates **Command Injection vulnerabilities** (aligned with **OWASP OTG-INPVAL-013**) on **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on `localhost`**. Upon completion, the script must generate a **professional, well-designed HTML report** in the style of **OWASP** and **OSCP penetration testing reports**.

---

## 🎯 Target Environment
- **Application**: DVWA (Damn Vulnerable Web Application)
- **Deployment**: XAMPP on `localhost`
- **URL**: `http://localhost/dvwa/`
- **Test Module**: Command Execution (`/dvwa/vulnerabilities/exec/`)
- **Authentication Required**: Yes (script must handle login and session)
- **Security Level**: Low (assumed for testing)
- **Prerequisites**: DVWA security level set to "Low" for maximum vulnerability exposure

---

## 🛠️ Script Requirements

### 1. **Core Functionality**
- **Authentication Automation**:
  - Log in to DVWA using provided credentials (e.g., `admin:password`).
  - Handle CSRF tokens (`user_token`) and maintain session cookies.
- **Command Injection Testing**:
  - Target the Command Execution module (`/dvwa/vulnerabilities/exec/`)
  - Test with a comprehensive set of command injection payloads:
    - **Basic Command Chaining**: `; whoami`, `&& whoami`, `| whoami`, `& whoami`
    - **Time-based Detection**: `; sleep 10`, `&& ping -c 10 127.0.0.1`, `| timeout 10`
    - **Blind Injection**: `; ifconfig > /tmp/output.txt`, `&& dir > C:\\temp\\output.txt`
    - **File System Interaction**: `; ls /`, `&& dir C:\\`, `; cat /etc/passwd`
    - **Reverse Shell Indicators**: `; nc -e /bin/sh`, `&& powershell -c`
    - **OS Detection**: `; uname -a`, `&& ver`
    - **Network Information**: `; ipconfig`, `&& ifconfig`, `; netstat -an`
  - Test payloads for both Unix/Linux and Windows command separators
  - Use time-based detection for blind command injection
  - Verify results by checking for:
    - Command output in response
    - Response timing anomalies
    - File creation/modification
- **Vulnerability Detection**:
  - Flag inputs that:
    - Execute system commands
    - Return command output in response
    - Show response timing delays
    - Process commands in unexpected ways
  - Differentiate between:
    - Simple command execution
    - Blind command injection
    - Time-based command injection
- **Session Handling**:
  - Maintain authenticated session throughout the test.
  - Re-authenticate if session expires.

### 2. **Reporting**
- Generate a **single, self-contained HTML report** (`command_injection_report.html`) with:
  - **Title**: "Command Injection Assessment – DVWA (OTG-INPVAL-013)"
  - **Executive Summary**: Brief overview of findings and risk.
  - **Test Details**:
    - Target URL
    - Vulnerability Type: Command Injection
    - OWASP Test ID: OTG-INPVAL-013
    - Risk Level: High
    - Date & Time of Test
  - **Methodology**:
    - Steps taken (login → endpoint identification → payload testing → analysis)
    - Tools used (script name, Python modules)
  - **Findings**:
    - Table of tested payloads and results
    - For each vulnerable input:
      - Command separator used
      - Payload used
      - Response evidence
      - Impact (e.g., RCE, information disclosure)
      - Proof of Concept (PoC)
    - Screenshots (if using Selenium for verification)
  - **Remediation Recommendations**:
    - Input validation and sanitization
    - Principle of least privilege
    - Web server configuration
    - Secure coding practices
  - **References**:
    - OWASP Testing Guide: OTG-INPVAL-013
    - CWE-77: Command Injection
    - OWASP Command Injection Cheat Sheet

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
- Use tabs or sections to separate different types of command injection findings

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
  - `--output`: Output report path (default: `reports/command_injection_report.html`)
  - `--timeout`: Request timeout (default: 15 seconds)
  - `--delay`: Delay between requests (default: 1 second)
- **Logging**:
  - Print progress to console
  - Save raw responses for debugging (optional)

---

## 🧾 Expected Output
- A Python script: `dvwa_command_injection.py`
- Generated HTML report: `command_injection_report.html` (or as specified)
- Report includes:
  - ✅ Vulnerability confirmed
  - ✅ Payloads tested
  - ✅ Risk assessment
  - ✅ Remediation advice
  - ✅ Professional presentation

---

## 📝 Example Usage
```bash
python dvwa_command_injection.py \
  --url http://localhost/dvwa \
  --username admin \
  --password password \
  --output reports/command_injection_$(date +%F).html