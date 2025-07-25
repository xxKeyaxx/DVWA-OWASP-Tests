# AI Coding Agent Prompt: HTTP Parameter Pollution Testing Script for DVWA (OTG-INPVAL-004)

## 📌 Overview
Create a Python-based automated testing script that identifies and validates **HTTP Parameter Pollution (HPP) vulnerabilities** (aligned with **OWASP OTG-INPVAL-004**) on **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on `localhost`**. Upon completion, the script must generate a **professional, well-designed HTML report** in the style of **OWASP** and **OSCP penetration testing reports**.

---

## 🎯 Target Environment
- **Application**: DVWA (Damn Vulnerable Web Application)
- **Deployment**: XAMPP on `localhost`
- **URL**: `http://localhost/dvwa/`
- **Test Modules**:
  - Command Execution (`/dvwa/vulnerabilities/exec/`)
  - Reflected XSS (`/dvwa/vulnerabilities/xss_r/`)
  - SQL Injection (`/dvwa/vulnerabilities/sqli/`)
  - Any GET-based input forms
- **Authentication Required**: Yes (script must handle login and session)
- **Security Level**: Low (assumed for testing)

---

## 🛠️ Script Requirements

### 1. **Core Functionality**
- **Authentication Automation**:
  - Log in to DVWA using provided credentials (e.g., `admin:password`).
  - Handle CSRF tokens (`user_token`) and maintain session cookies.
- **HTTP Parameter Pollution Testing**:
  - Identify endpoints that accept GET parameters.
  - For each parameter, test multiple pollution techniques:
    - **Duplicate Parameters**: `?param=value1&param=value2`
    - **Semicolon Separation**: `?param=value1;value2` (if server supports it)
    - **Comma Separation**: `?param=value1,value2` 
    - **Array Notation**: `?param[]=value1&param[]=value2`
    - **Mixed Case**: `?Param=value1&param=value2`
  - Test with both benign and malicious payloads:
    - Benign: `test`, `dummy`
    - Malicious: XSS payloads, command injection attempts
- **Vulnerability Detection**:
  - Flag endpoints that:
    - Process only the first occurrence of a parameter
    - Process only the last occurrence of a parameter
    - Concatenate parameter values
    - Process all values in an unexpected way
    - Allow bypass of input validation through parameter pollution
- **Session Handling**:
  - Maintain authenticated session throughout the test.
  - Re-authenticate if session expires.

### 2. **Reporting**
- Generate a **single, self-contained HTML report** (`http_parameter_pollution_report.html`) with:
  - **Title**: "HTTP Parameter Pollution Assessment – DVWA (OTG-INPVAL-004)"
  - **Executive Summary**: Brief overview of findings and risk.
  - **Test Details**:
    - Target URL
    - Vulnerability Type: HTTP Parameter Pollution
    - OWASP Test ID: OTG-INPVAL-004
    - Risk Level: Medium
    - Date & Time of Test
  - **Methodology**:
    - Steps taken (login → endpoint discovery → parameter pollution → analysis)
    - Tools used (script name, Python modules)
  - **Findings**:
    - Table of tested endpoints and parameters
    - For each vulnerable endpoint:
      - Parameter name
      - Pollution technique used
      - Server response/behavior
      - Impact (e.g., input validation bypass, unexpected behavior)
      - Evidence (response snippets or status codes)
    - Proof of Concept (PoC) code
  - **Remediation Recommendations**:
    - Validate and sanitize all input parameters
    - Use server-side frameworks that handle parameter pollution properly
    - Implement proper input validation
    - Log and monitor suspicious parameter patterns
  - **References**:
    - OWASP Testing Guide: OTG-INPVAL-004
    - CWE-834: Excessive Iteration
    - OWASP HTTP Parameter Pollution Cheat Sheet

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
  - `datetime`, `os`, `json` – for logging and data
- **Command-Line Arguments**:
  - `--url`: Target URL (default: `http://localhost/dvwa`)
  - `--username`: DVWA username (default: `admin`)
  - `--password`: DVWA password (default: `password`)
  - `--output`: Output report path (default: `reports/hpp_report.html`)
  - `--timeout`: Request timeout (default: 10 seconds)
- **Logging**:
  - Print progress to console
  - Save raw responses for debugging (optional)

---

## 🧾 Expected Output
- A Python script: `dvwa_http_parameter_pollution.py`
- Generated HTML report: `http_parameter_pollution_report.html` (or as specified)
- Report includes:
  - ✅ Vulnerability confirmed
  - ✅ Endpoints tested
  - ✅ Parameters analyzed
  - ✅ Risk assessment
  - ✅ Remediation advice
  - ✅ Professional presentation

---

## 📝 Example Usage
```bash
python dvwa_http_parameter_pollution.py \
  --url http://localhost/dvwa \
  --username admin \
  --password password \
  --output reports/hpp_$(date +%F).html