# AI Coding Agent Prompt: DVWA Stack Trace Analysis Script & OSCP-Style Report Generator

## Objective

Create a Python script that automates the testing of **OTG-ERR-002 – Analysis of Stack Traces** on a **DVWA (Damn Vulnerable Web App)** instance running locally via **XAMPP on localhost**. The script must detect and extract stack traces from error responses and generate a professional, well-structured **HTML report** in **OWASP/OSCP-style formatting**, suitable for penetration testing documentation.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation expert and offensive security script developer. Your task is to write a **Python script** that performs automated testing for **OTG-ERR-002 (Analysis of Stack Traces)** as defined in the OWASP Testing Guide v4.2. The target is **DVWA hosted on localhost using XAMPP** (e.g., `http://localhost/dvwa`).

### Requirements

#### 1. **Target Environment**
- Application: DVWA (Damn Vulnerable Web App)
- Host: `http://localhost`
- Path: `/dvwa`
- Assumed login credentials: `admin:password` (default for DVWA)
- Security level: Set to **Low** (automatically via script if possible)

#### 2. **Functionality of the Script**
- Automatically log in to DVWA using the provided credentials.
- Navigate to vulnerable modules (especially **Command Injection**, **SQL Injection**, **File Inclusion**, and **XSS**) and **trigger intentional errors** by injecting malformed inputs.
- Capture HTTP responses and **analyze them for stack traces** (e.g., PHP errors, database exceptions, backtraces, file paths, server configurations).
- Detect presence of:
  - Full path disclosure (FPD)
  - PHP fatal/warning notices
  - Database error messages (MySQL, etc.)
  - Call stacks or backtraces
  - Server/software version leaks
- Log all findings with:
  - URL
  - Request method & payload
  - HTTP status code
  - Extracted error message / stack trace
  - Timestamp

#### 3. **Output: OSCP-Style HTML Report**
Generate a clean, professional **HTML report** titled:  
`OTG-ERR-002 - Analysis of Stack Traces - DVWA Localhost Assessment`

The report must follow **OSCP/OWASP reporting standards** and include:

- **Title Section**: Test Name, Target, Date, Author (optional: "AI Security Agent")
- **Executive Summary**: Brief overview of findings (e.g., "Stack traces were observed exposing server paths and PHP configurations.")
- **Test Details**:
  - OWASP Test ID: OTG-ERR-002
  - Test Objective
  - Description of stack trace risks
- **Methodology**:
  - Tools used (Python, requests, BeautifulSoup)
  - Steps taken to trigger errors
- **Findings Table**:
  | Vulnerability | URL | Payload | HTTP Code | Evidence (Truncated Error) | Severity |
  |---------------|-----|---------|-----------|-----------------------------|----------|
  Include at least 3–5 real examples from DVWA.
- **Evidence Snippets**:
  - Code blocks showing raw stack traces (escaped HTML)
- **Remediation Recommendations**:
  - Disable display_errors in php.ini
  - Use custom error pages
  - Input validation
- **Conclusion**: Summary of risk level and overall exposure.
- **Styling**: Use **OSCP-like design**:
  - Monospace fonts for code
  - Dark blue/gray theme with light text
  - Clean headers and section dividers
  - Report footer with "Generated on [datetime]"

#### 4. **Technical Specifications**
- Language: **Python 3**
- Libraries: `requests`, `BeautifulSoup4`, `re`, `time`, `os`, `html`
- Session handling with cookies for DVWA login
- Handle CSRF tokens (DVWA requires `user_token`)
- Use `verify=False` only if self-signed SSL is involved (unlikely on localhost XAMPP)
- Save HTML report to: `./reports/OTG-ERR-002_Stack_Trace_Report.html`
- Create `/reports` directory if it doesn’t exist

#### 5. **Error Handling & Safety**
- Graceful handling of connection errors
- No destructive payloads
- Script must not modify DVWA beyond triggering errors
- Add delays between requests to avoid lockouts

#### 6. **Example Output Snippet (HTML)**
```html
<div class="section">
  <h2>4. Findings</h2>
  <table>
    <tr><th>Vulnerability</th><th>URL</th><th>Payload</th><th>Status</th><th>Evidence</th><th>Severity</th></tr>
    <tr>
      <td>PHP Stack Trace</td>
      <td>/dvwa/vulnerabilities/exec/</td>
      <td>; ls -la /</td>
      <td>200</td>
      <td>Fatal error: Uncaught mysqli_sql_exception: Access denied...</td>
      <td>Medium</td>
    </tr>
  </table>
</div>