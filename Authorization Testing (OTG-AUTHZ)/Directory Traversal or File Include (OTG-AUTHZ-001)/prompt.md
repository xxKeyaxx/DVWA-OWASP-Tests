# AI Prompt: Directory Traversal Vulnerability Testing Script for DVWA with OSCP-Style HTML Report

## Objective

Create a detailed prompt for an AI coding agent to generate a Python script that automatically tests for **Directory Traversal / Local File Inclusion (LFI)** vulnerabilities (OWASP OTG-AUTHZ-001) on **DVWA (Damn Vulnerable Web App)** running locally via **XAMPP on localhost**. The script should perform active testing, validate the vulnerability, and generate a professional **OWASP/OSCP-style penetration test report** in a well-structured and visually appealing **HTML format**.

---

## Prompt for AI Coding Agent

You are a skilled offensive security automation engineer. Your task is to write a **Python script** that:

1. **Automatically tests** the **File Inclusion vulnerability** in **DVWA (Difficulty: Low)** at `http://localhost/dvwa`.
2. Authenticates to DVWA using default credentials (`admin:password`).
3. Navigates to the **"File Inclusion"** section.
4. Exploits the **directory traversal vulnerability** by attempting to read sensitive local files such as:
   - `C:\xampp\php\php.ini`
   - `C:\Windows\System32\drivers\etc\hosts`
   - `C:\xampp\apache\conf\httpd.conf`
   *(Adjust paths for Windows; if testing on Linux, use `/etc/passwd`, `/etc/hosts`, etc.)*
5. Confirms exploitation by analyzing HTTP responses.
6. Logs all requests, payloads, and responses for reporting.
7. Generates a **professional penetration testing report** in **HTML format**, styled in the **OSCP/OWASP report style**:
   - Clean, monospace font (e.g., `Courier New`, `Consolas`)
   - Dark background with light text (or classic OSCP light theme)
   - Sections with headers and code blocks
   - Vulnerability title, risk level (High), description, impact, remediation
   - Steps to reproduce with request/response examples
   - Screenshot (optional, if possible via headless browser)
   - References to OWASP (OTG-AUTHZ-001) and CVE (if applicable)

---

### Script Requirements

- **Language**: Python 3
- **Libraries**: `requests`, `BeautifulSoup4`, `os`, `datetime`, `html` (for escaping)
- **Features**:
  - Session handling with `requests.Session()`
  - CSRF token extraction from DVWA login and security pages
  - Support for DVWA security level "Low"
  - Payloads using common traversal patterns (`../../../../`)
  - Output: Success/failure per file tested
  - HTML report generation with embedded CSS (no external files)

---

### Report Structure (HTML Output)

Generate a standalone HTML file named:  
`OSCP_Report_DVWA_LFI_Localhost_YYYYMMDD.html`

#### Report Sections:
1. **Title Page**: 
   - "Penetration Test Report"
   - Target: `http://localhost/dvwa`
   - Date, Author: "Automated Security Agent"
   - Report Classification: `UNCLASSIFIED`

2. **Executive Summary**:
   - Brief overview of findings
   - Risk rating: **High**
   - Summary of impact

3. **Vulnerability Details**:
   - **Name**: Directory Traversal / Local File Inclusion
   - **OWASP ID**: OTG-AUTHZ-001
   - **CVE**: N/A (or hypothetical CVE-2025-1337 if illustrative)
   - **Risk Level**: High
   - **URL**: `http://localhost/dvwa/vulnerabilities/fi/`
   - **Description**: Explain how the vulnerability allows reading arbitrary files.
   - **Impact**: System file disclosure, potential credential/config leaks.
   - **Remediation**: Input validation, use of whitelists, secure file handling.

4. **Technical Analysis**:
   - Step-by-step exploitation process
   - Request/Response samples (formatted as code blocks)
   - Payloads used
   - Proof of Concept (PoC) with file contents retrieved

5. **Conclusion**:
   - Reiteration of risk
   - Recommendation to fix

6. **Appendices**:
   - Full list of tested payloads
   - References:
     - [OWASP Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
     - DVWA Documentation

---

### Additional Notes

- Ensure the script checks if DVWA is reachable before proceeding.
- Handle exceptions (e.g., connection errors, timeouts).
- Do **not** perform destructive actions.
- The report should be **self-contained** (inline CSS, no JS).
- Use realistic but safe payloads.

---

### Final Output

The AI should return:
1. A complete **Python script** (`dvwa_lfi_tester.py`)
2. A sample **HTML report** (generated output example)
3. Instructions to run the script

> ✅ This prompt is designed for educational use on a **local lab environment only**.