# AI Coding Agent Prompt: Incubated Vulnerabilities Testing Script for DVWA (OTG-INPVAL-015)

## 📌 Overview
Create a Python-based automated testing script that identifies and validates **Incubated (Delayed) Vulnerabilities** (aligned with **OWASP OTG-INPVAL-015**) on **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on `localhost`**. Upon completion, the script must generate a **professional, well-designed HTML report** in the style of **OWASP** and **OSCP penetration testing reports**.

---

## 🎯 Target Environment
- **Application**: DVWA (Damn Vulnerable Web Application)
- **Deployment**: XAMPP on `localhost`
- **URL**: `http://localhost/dvwa/`
- **Test Modules**:
  - Stored XSS (`/dvwa/vulnerabilities/xss_s/`)
  - File Upload (`/dvwa/vulnerabilities/upload/`)
  - Command Execution (if stored output)
  - Any input that is stored and later processed
- **Authentication Required**: Yes (script must handle login and session)
- **Security Level**: Low (assumed for testing)
- **Prerequisites**: DVWA security level set to "Low" for maximum vulnerability exposure

---

## 🛠️ Script Requirements

### 1. **Core Functionality**
- **Authentication Automation**:
  - Log in to DVWA using provided credentials (e.g., `admin:password`).
  - Handle CSRF tokens (`user_token`) and maintain session cookies.
- **Incubated Vulnerabilities Testing**:
  - Identify inputs that store data for later processing (incubation)
  - Test with various incubated payloads:
    - **Stored XSS**: `<script>alert("INCUBATED-XSS")</script>`, `<img src="x" onerror="alert('XSS')">`
    - **File Upload with Malicious Content**: Upload files with embedded scripts or commands
    - **Delayed Command Execution**: Payloads that execute when data is later processed
    - **Log Poisoning**: Inject payloads that execute when logs are viewed
    - **Email Injection**: If email functionality exists
  - Implement **delayed verification** to check for incubated effects:
    - Wait specified time intervals (e.g., 5 seconds, 30 seconds)
    - Re-check the stored content for processing
    - Verify if payloads were executed when the data was later accessed
- **Vulnerability Detection**:
  - Flag inputs that:
    - Store malicious payloads
    - Process stored payloads in a vulnerable way
    - Execute payloads when the data is later accessed
    - Show delayed effects of injection
  - Use time-based detection for delayed vulnerabilities
  - Verify results by checking for:
    - Payload execution when data is accessed
    - Changes in stored content over time
    - Unexpected behavior during delayed verification
- **Session Handling**:
  - Maintain authenticated session throughout the test.
  - Re-authenticate if session expires.

### 2. **Reporting**
- Generate a **single, self-contained HTML report** (`incubated_vulnerabilities_report.html`) with:
  - **Title**: "Incubated Vulnerabilities Assessment – DVWA (OTG-INPVAL-015)"
  - **Executive Summary**: Brief overview of findings and risk.
  - **Test Details**:
    - Target URL
    - Vulnerability Type: Incubated/Delayed Vulnerabilities
    - OWASP Test ID: OTG-INPVAL-015
    - Risk Level: High
    - Date & Time of Test
  - **Methodology**:
    - Steps taken (login → endpoint discovery → payload injection → delayed verification → analysis)
    - Tools used (script name, Python modules)
  - **Findings**:
    - Table of tested endpoints and payloads
    - For each vulnerable input:
      - Input field name
      - Incubated payload used
      - Verification method
      - Delay period
      - Impact (e.g., delayed XSS, stored code execution)
      - Evidence (response snippets or status codes)
    - Proof of Concept (PoC) code
  - **Remediation Recommendations**:
    - Input validation and sanitization
    - Output encoding
    - Content Security Policy (CSP)
    - Regular monitoring of stored content
  - **References**:
    - OWASP Testing Guide: OTG-INPVAL-015
    - CWE-79: XSS
    - CWE-94: Code Injection

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
- Use tabs or sections to separate different types of incubated vulnerabilities

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
  - `--output`: Output report path (default: `reports/incubated_report.html`)
  - `--timeout`: Request timeout (default: 15 seconds)
  - `--delay`: Delay between requests (default: 1 second)
  - `--verification-delay`: Delay for incubation verification (default: 5 seconds)
- **Logging**:
  - Print progress to console
  - Save raw responses for debugging (optional)

---

## 🧾 Expected Output
- A Python script: `dvwa_incubated_vulnerabilities.py`
- Generated HTML report: `incubated_vulnerabilities_report.html` (or as specified)
- Report includes:
  - ✅ Vulnerability confirmed
  - ✅ Endpoints tested
  - ✅ Payloads used
  - ✅ Risk assessment
  - ✅ Remediation advice
  - ✅ Professional presentation

---

## 📝 Example Usage
```bash
python dvwa_incubated_vulnerabilities.py \
  --url http://localhost/dvwa \
  --username admin \
  --password password \
  --output reports/incubated_$(date +%F).html \
  --verification-delay 10