# AI Coding Agent Prompt: Session Management Bypass Test Script for DVWA (OTG-SESS-001)

## Objective

Create a Python-based automated testing script that evaluates the **Session Management Schema** of Damn Vulnerable Web Application (DVWA) running on a local XAMPP server (`http://localhost/dvwa`). The script should specifically target **OTG-SESS-001 - Bypassing Session Management Schema** as defined in the OWASP Testing Guide.

Upon completion, the script must generate a professional, well-structured, and visually appealing **HTML report** in the style of **OSCP (Offensive Security Certified Professional)** and **OWASP** documentation standards.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs automated testing for **Session Management Bypass (OTG-SESS-001)** on **DVWA (Damn Vulnerable Web Application)** hosted locally via **XAMPP** at `http://localhost/dvwa`.

> ### Requirements

> #### 1. **Target Environment**
> - DVWA is running on `http://localhost/dvwa`
> - The script assumes DVWA is configured and accessible
> - Default credentials: `admin:password` (used only for login simulation)
> - Security level: set to **Low** for test consistency (optional: allow override via config)

> #### 2. **Test Scope – OTG-SESS-001**
> The script must:
> - Simulate login to obtain a valid session cookie (`PHPSESSID`)
> - Attempt to **reuse** the session ID from another context (e.g., different user role, after logout, or across sessions)
> - Test for **session fixation**:
>   - Pre-set `PHPSESSID` before login
>   - Verify if the application accepts and uses the attacker-supplied session ID
> - Test for **session persistence after logout**
> - Check if session tokens are regenerated upon privilege escalation (e.g., login to admin)
> - Validate session expiration mechanisms (optional: time-based check)

> #### 3. **Script Functionality**
> - Use `requests` and `BeautifulSoup` (or equivalent) to interact with DVWA
> - Handle CSRF tokens where necessary (e.g., login form)
> - Log all HTTP requests and responses for debugging
> - Output structured findings (pass/fail) for each test case
> - Be non-destructive (avoid brute-force or DoS)

> #### 4. **Report Generation**
> After testing, generate a **standalone HTML report** with:
> - **Title**: "Session Management Bypass Test – OTG-SESS-001"
> - **Target**: `http://localhost/dvwa`
> - **Test Date & Time**
> - **Executive Summary**
> - **Test Details**:
>   - Test Case Descriptions
>   - Methodology
>   - Request/Response Snippets (redacted if sensitive)
>   - Findings (Pass/Fail with explanation)
> - **Risk Rating**: Medium/High (based on OWASP Risk Rating)
> - **Remediation Recommendations**
> - **References**: OWASP Session Management Cheat Sheet, OTG-SESS-001
> 
> The report must follow **OSCP-style formatting**:
> - Monospace font (e.g., `Courier New`, `Consolas`)
> - Dark background with light text (optional: green/blue accent)
> - Terminal-like aesthetic
> - Clear section headers and code blocks
> - Professional layout using embedded CSS (no external dependencies)
> - Include a simple header/footer with tool name and page numbers (if applicable)

> #### 5. **Output**
> - Save the HTML report as: `OTG-SESS-001_Session_Bypass_Report.html`
> - Print summary to console upon completion

> #### 6. **Additional Notes**
> - Include comments in the script for clarity
> - Make the script configurable (e.g., via variables at the top)
> - Ensure compatibility with Python 3.7+
> - Handle common exceptions (e.g., connection refused, login failure)

> Return only the **complete Python script**, fully self-contained, with embedded HTML template for the report. No markdown, no explanation—just the code.

---

## Deliverable

The AI agent should return a `.py` file that satisfies the above prompt. This `.md` file serves as the instruction set for generating that script.

You may now proceed to generate the Python script based on this prompt.