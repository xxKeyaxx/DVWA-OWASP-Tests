# AI Coding Agent Prompt: DVWA Reflected XSS Testing Script & Report Generator

## Objective

Create a Python-based automated testing script that evaluates **Reflected Cross-Site Scripting (OTG-INPVAL-001)** vulnerabilities in **Damn Vulnerable Web Application (DVWA)** hosted on a local XAMPP server (`http://localhost/dvwa`). The script must test the vulnerability across **all security levels (Low, Medium, High, Impossible)** and generate a professional, well-designed **HTML report** in **OWASP/OSCP-style formatting**.

---

## Prompt for AI Coding Agent

You are an expert security automation developer. Your task is to write a **Python script** that performs the following:

### 1. **Environment Setup & Configuration**
- Assume DVWA is running on `http://localhost/dvwa`
- The script should:
  - Handle login to DVWA using default credentials (`admin:password`)
  - Navigate to the **"Reflected Cross Site Scripting"** page
  - Automatically cycle through **all security levels**: `Low`, `Medium`, `High`, `Impossible`
  - Adjust testing methodology based on the current security level (e.g., bypass techniques for Medium/High)

### 2. **Testing Methodology**
For each security level:
- **Inject a series of XSS payloads** into the "Name" input field of the Reflected XSS page
- Payloads should include:
  - Basic alert: `<script>alert('XSS')</script>`
  - Encoded variant: `<img src=x onerror=alert('XSS')>`
  - Case variation: `<ScRiPt>alert('XSS')</ScRiPt>`
  - Event-based: `"><svg/onload=alert('XSS')>`
  - URL-encoded: `%3Cscript%3Ealert('XSS')%3C/script%3E`
- For **Medium** level: Attempt payloads that avoid filtering (e.g., without `<script>`)
- For **High** level: Use advanced obfuscation or DOM-based injection if applicable
- For **Impossible**: Confirm mitigation and show why exploitation fails

### 3. **Validation**
- Check the HTTP response for execution indicators:
  - Presence of injected payload in response
  - Detection of JavaScript execution (via response content analysis)
  - Use of a headless browser (e.g., Selenium) is preferred for accurate detection

### 4. **Reporting**
After testing all levels, generate a **single, styled HTML report** with the following sections:

#### Report Structure
- **Title**: `OWASP OSCP-Style Security Assessment Report`
- **Vulnerability**: `Reflected Cross-Site Scripting (OTG-INPVAL-001)`
- **Target**: `http://localhost/dvwa`
- **Author**: `Automated Security Scanner`
- **Date**: `[Current Date]`

#### Sections:
1. **Executive Summary**
   - Brief description of XSS and impact
   - Overall risk rating (e.g., High)
   - Summary of findings per security level

2. **Technical Findings**
   - Table with columns: `Security Level`, `Payload Used`, `Success`, `Evidence (Response Snippet)`, `Notes`
   - For each level, show:
     - Whether exploitation was successful
     - Payload used
     - Snippet of vulnerable response (sanitized for display)
     - Explanation of filter bypass (if applicable)

3. **Proof of Concept**
   - Screenshots (optional, if Selenium is used and screenshots enabled)
   - Or code snippets showing payload injection and response

4. **Remediation Recommendations**
   - Input validation
   - Output encoding
   - Use of Content Security Policy (CSP)
   - Secure coding practices

5. **References**
   - OWASP XSS Page: [https://owasp.org/www-community/attacks/xss/](https://owasp.org/www-community/attacks/xss/)
   - DVWA GitHub: [https://github.com/digininja/DVWA](https://github.com/digininja/DVWA)

### 5. **Report Design Requirements**
- Use **embedded CSS** for styling
- Clean, professional layout with:
  - Dark header with white text
  - Alternating row colors in tables
  - Monospace font for payloads
  - Responsive design
  - OSCP-like aesthetic (simple, functional, penetration-testing style)

### 6. **Script Requirements**
- Use `requests`, `BeautifulSoup`, and `Selenium` (for DOM interaction)
- Handle CSRF tokens (DVWA’s `user_token`)
- Automatically set security level via backend request or UI navigation
- Save report to `xss_reflected_report.html`
- Include error handling (e.g., if DVWA is unreachable)

### 7. **Output**
- The script should run via command line: `python dvwa_xss_tester.py`
- No interactive input required
- Final output: A complete, self-contained HTML report

---

## Example Usage

```bash
python dvwa_xss_tester.py
[*] Logging into DVWA...
[*] Testing Reflected XSS at Low level... Success!
[*] Testing Reflected XSS at Medium level... Success!
[*] Testing Reflected XSS at High level... Partial success!
[*] Testing Reflected XSS at Impossible level... Failed (expected)
[+] Report generated: xss_reflected_report.html