# AI Coding Agent Prompt: HTTP Splitting/Smuggling Testing Script for DVWA (OTG-INPVAL-016)

## 📌 Overview
Create a Python-based automated testing script that identifies and validates **HTTP Response Splitting and HTTP Smuggling vulnerabilities** (aligned with **OWASP OTG-INPVAL-016**) on **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on `localhost`**. Upon completion, the script must generate a **professional, well-designed HTML report** in the style of **OWASP** and **OSCP penetration testing reports**.

---

## 🎯 Target Environment
- **Application**: DVWA (Damn Vulnerable Web Application)
- **Deployment**: XAMPP on `localhost`
- **URL**: `http://localhost/dvwa/`
- **Test Modules**:
  - Any endpoint that reflects user input in HTTP headers
  - Any endpoint that processes HTTP requests with headers
  - Any input that could influence HTTP responses
- **Authentication Required**: Yes (script must handle login and session)
- **Security Level**: Low (assumed for testing)
- **Prerequisites**: DVWA security level set to "Low" for maximum vulnerability exposure

---

## 🛠️ Script Requirements

### 1. **Core Functionality**
- **Authentication Automation**:
  - Log in to DVWA using provided credentials (e.g., `admin:password`).
  - Handle CSRF tokens (`user_token`) and maintain session cookies.
- **HTTP Splitting/Smuggling Testing**:
  - Identify endpoints that reflect user input in HTTP headers or could be influenced by HTTP request manipulation
  - Test with various HTTP splitting/smuggling payloads:
    - **HTTP Response Splitting**: 
      - `%0D%0ASet-Cookie: test=value` (CRLF injection)
      - `%0D%0AContent-Length: 0%0D%0A%0D%0AHTTP/1.1 200 OK%0D%0AContent-Type: text/html%0D%0AContent-Length: 10%0D%0A%0D%0AHELLO WORLD`)
    - **HTTP Request Smuggling**:
      - `Transfer-Encoding: chunked` with malicious chunking
      - `Content-Length` header manipulation
      - `Transfer-Encoding` and `Content-Length` conflicts
    - **CRLF Injection**: `%0D%0A` sequences to inject headers
    - **Cache Poisoning**: Headers that could influence caching behavior
  - Test payloads in various contexts:
    - URL parameters
    - Headers (if possible)
    - Form inputs that might influence headers
  - Use **raw socket communication** for HTTP smuggling tests to bypass high-level HTTP libraries
  - Verify results by checking for:
    - Multiple HTTP responses
    - Unexpected header modifications
    - Cache poisoning indicators
    - Response splitting in raw responses
- **Vulnerability Detection**:
  - Flag endpoints that:
    - Process CRLF sequences in headers
    - Show evidence of response splitting
    - Process conflicting `Content-Length` and `Transfer-Encoding` headers
    - Reflect user input in HTTP headers without proper sanitization
  - Use time-based detection for blind HTTP smuggling
  - Verify results by analyzing raw HTTP responses for splitting/smuggling indicators
- **Session Handling**:
  - Maintain authenticated session throughout the test.
  - Re-authenticate if session expires.

### 2. **Reporting**
- Generate a **single, self-contained HTML report** (`http_splitting_smuggling_report.html`) with:
  - **Title**: "HTTP Splitting/Smuggling Assessment – DVWA (OTG-INPVAL-016)"
  - **Executive Summary**: Brief overview of findings and risk.
  - **Test Details**:
    - Target URL
    - Vulnerability Type: HTTP Splitting/Smuggling
    - OWASP Test ID: OTG-INPVAL-016
    - Risk Level: High
    - Date & Time of Test
  - **Methodology**:
    - Steps taken (login → endpoint discovery → payload testing → analysis)
    - Tools used (script name, Python modules)
  - **Findings**:
    - Table of tested endpoints and payloads
    - For each vulnerable endpoint:
      - Attack type (Splitting/Smuggling)
      - Payload used
      - Raw response evidence
      - Impact (e.g., cache poisoning, session fixation)
      - Proof of Concept (PoC)
    - Screenshots of raw HTTP responses
  - **Remediation Recommendations**:
    - Input validation and sanitization
    - Proper header handling
    - Web server configuration
    - Secure coding practices
  - **References**:
    - OWASP Testing Guide: OTG-INPVAL-016
    - CWE-113: HTTP Response Splitting
    - CWE-444: HTTP Request Smuggling

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
- Use tabs or sections to separate HTTP Splitting and HTTP Smuggling findings

### 4. **Technical Specifications**
- **Language**: Python 3.7+
- **Libraries**:
  - `requests` – for standard HTTP handling
  - `socket` – for raw HTTP communication (smuggling)
  - `BeautifulSoup4` – for parsing HTML
  - `argparse` – for CLI arguments
  - `datetime`, `os`, `json`, `time` – for logging and data
- **Command-Line Arguments**:
  - `--url`: Target URL (default: `http://localhost/dvwa`)
  - `--username`: DVWA username (default: `admin`)
  - `--password`: DVWA password (default: `password`)
  - `--output`: Output report path (default: `reports/http_splitting_report.html`)
  - `--timeout`: Request timeout (default: 15 seconds)
  - `--delay`: Delay between requests (default: 1 second)
- **Logging**:
  - Print progress to console
  - Save raw responses for debugging (optional)

---

## 🧾 Expected Output
- A Python script: `dvwa_http_splitting_smuggling.py`
- Generated HTML report: `http_splitting_smuggling_report.html` (or as specified)
- Report includes:
  - ✅ Vulnerability confirmed
  - ✅ Payloads tested
  - ✅ Risk assessment
  - ✅ Remediation advice
  - ✅ Professional presentation

---

## 📝 Example Usage
```bash
python dvwa_http_splitting_smuggling.py \
  --url http://localhost/dvwa \
  --username admin \
  --password password \
  --output reports/http_splitting_$(date +%F).html