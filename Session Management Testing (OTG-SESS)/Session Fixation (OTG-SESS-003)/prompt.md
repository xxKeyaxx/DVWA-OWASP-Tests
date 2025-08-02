# AI Coding Agent Prompt: Session Fixation Test Script for DVWA (OTG-SESS-003)

## Objective

Create a Python-based automated testing script that evaluates **Session Fixation vulnerabilities** in Damn Vulnerable Web Application (DVWA) running on a local XAMPP server (`http://localhost/dvwa`). The script should specifically target **OTG-SESS-003 - Testing for Session Fixation** as defined in the OWASP Testing Guide.

Upon completion, the script must generate a professional, well-structured, and visually appealing **HTML report** in the style of **OSCP (Offensive Security Certified Professional)** and **OWASP** documentation standards.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs automated testing for **Session Fixation (OTG-SESS-003)** on **DVWA (Damn Vulnerable Web Application)** hosted locally via **XAMPP** at `http://localhost/dvwa`.

> ### Requirements

> #### 1. **Target Environment**
> - DVWA is running on `http://localhost/dvwa`
> - The script assumes DVWA is properly configured and accessible
> - Default credentials: `admin:password` (used only for login simulation)
> - Security level: set to **Low** for test consistency (optional: allow override via config)
> - Script must work on HTTP (no HTTPS required)

> #### 2. **Test Scope – OTG-SESS-003**
> The script must:
> - Simulate a session fixation attack by pre-setting a known `PHPSESSID` cookie
> - Attempt to authenticate with the fixed session ID
> - Verify whether the application accepts and retains the attacker-supplied session ID after login
> - Check if the session ID is properly regenerated upon successful authentication
> - Test for session invalidation after logout
> - Validate that new sessions are issued on privilege changes (if applicable)
> - Identify if the application is vulnerable to session fixation based on OWASP criteria

> #### 3. **Script Functionality**
> - Use `requests` and `BeautifulSoup` (or equivalent) to interact with DVWA
> - Handle CSRF tokens where necessary (e.g., login form)
> - Implement two-phase testing:
>   1. **Attack Phase**: Set a fixed session ID and attempt login
>   2. **Verification Phase**: Confirm if the fixed session ID persists post-login
> - Log all relevant HTTP interactions (cookies, status codes, redirects)
> - Output structured findings (Pass/Fail) for session fixation vulnerability
> - Be non-destructive and safe for local testing

> #### 4. **Report Generation**
> After testing, generate a **standalone HTML report** with:
> - **Title**: "Session Fixation Test – OTG-SESS-003"
> - **Target**: `http://localhost/dvwa`
> - **Test Date & Time**
> - **Executive Summary**
> - **Test Details**:
>   - Methodology (step-by-step attack flow)
>   - Request/Response analysis
>   - Session ID tracking before and after login
>   - Evidence of vulnerability or mitigation
>   - Findings with clear Pass/Fail status
> - **Risk Rating**: High (if vulnerable), otherwise Medium/Low
> - **CVSS Score Estimate** (based on exploitability and impact)
> - **Remediation Recommendations** (e.g., regenerate session IDs on login)
> - **References**: OWASP Session Fixation, OTG-SESS-003, CWE-384, CVE examples
> 
> The report must follow **OSCP-style formatting**:
> - Monospace font (e.g., `Courier New`, `Consolas`)
> - Dark background with light text (black/gray theme with green/blue accents)
> - Terminal-like aesthetic
> - Clear section headers and code blocks
> - Responsive layout using embedded CSS (no external dependencies)
> - Include header/footer with tool name and page numbers (if applicable)

> #### 5. **Output**
> - Save the HTML report as: `OTG-SESS-003_Session_Fixation_Report.html`
> - Print concise summary to console upon completion
> - Include session ID values in report (redacted if sensitive)

> #### 6. **Additional Notes**
> - Include comments in the script for clarity
> - Make the script configurable via variables at the top (URLs, credentials, etc.)
> - Ensure compatibility with Python 3.7+
> - Handle common exceptions (e.g., connection refused, login failure, CSRF token missing)
> - The script should not require external tools beyond `requests` and `beautifulsoup4`

> Return only the **complete Python script**, fully self-contained, with embedded HTML template for the report. No markdown, no explanation—just the code.

---

## Deliverable

The AI agent should return a `.py` file that satisfies the above prompt. This `.md` file serves as the instruction set for generating that script.

You may now proceed to generate the Python script based on this prompt.