# AI Coding Agent Prompt: Logout Functionality Test Script for DVWA (OTG-SESS-006)

## Objective

Create a Python-based automated testing script that evaluates **Logout Functionality** in Damn Vulnerable Web Application (DVWA) running on a local XAMPP server (`http://localhost/dvwa`). The script should specifically target **OTG-SESS-006 - Testing for Logout Functionality** as defined in the OWASP Testing Guide.

Upon completion, the script must generate a professional, well-structured, and visually appealing **HTML report** in the style of **OSCP (Offensive Security Certified Professional)** and **OWASP** documentation standards.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs automated testing for **Logout Functionality (OTG-SESS-006)** on **DVWA (Damn Vulnerable Web Application)** hosted locally via **XAMPP** at `http://localhost/dvwa`.

> ### Requirements

> #### 1. **Target Environment**
> - DVWA is running on `http://localhost/dvwa`
> - The script assumes DVWA is properly configured and accessible
> - Default credentials: `admin:password` (used only for login simulation)
> - Security level: test at **Low**, **Medium**, and **High** levels
> - Script must work on HTTP (no HTTPS required)

> #### 2. **Test Scope – OTG-SESS-006**
> The script must:
> - Log in to DVWA with valid credentials
> - Test the logout functionality by:
>   - Verifying that the logout endpoint properly terminates the session
>   - Checking if session tokens are invalidated on the server side
>   - Testing if the session remains valid after logout (session reuse)
>   - Verifying that the user is redirected to the login page after logout
>   - Testing if cached pages can be accessed after logout
>   - Checking for proper session destruction (not just client-side cookie removal)
> - Test session invalidation across different security levels
> - Validate that session identifiers are not reused after logout
> - Check if the application implements secure logout best practices

> #### 3. **Script Functionality**
> - Use `requests` and `BeautifulSoup` (or equivalent) to interact with DVWA
> - Handle CSRF tokens where necessary
> - Implement comprehensive logout testing:
>   1. Login → Logout → Attempt access to protected page
>   2. Check session cookie status after logout
>   3. Test session reuse with old session ID
>   4. Verify redirection after logout
>   5. Test at multiple security levels
> - Maintain session state throughout testing
> - Output structured findings with evidence (HTTP status codes, response content)
> - Be non-destructive and safe for local testing

> #### 4. **Report Generation**
> After testing, generate a **standalone HTML report** with:
> - **Title**: "Logout Functionality Test – OTG-SESS-006"
> - **Target**: `http://localhost/dvwa`
> - **Test Date & Time**
> - **Executive Summary**
> - **Test Details**:
>   - Methodology (step-by-step testing approach)
>   - Test results for each security level
>   - Session validation before/after logout
>   - HTTP request/response analysis
>   - Evidence of proper or improper session termination
>   - Findings with clear Pass/Fail status
> - **Risk Rating**: High (if logout is ineffective), otherwise Low
> - **Remediation Recommendations** (e.g., "Properly invalidate sessions server-side", "Clear session data")
> - **References**: OWASP Logout, OTG-SESS-006, CWE-613 (Insufficient Session Expiration)
> 
> The report must follow **OSCP-style formatting**:
> - Monospace font (e.g., `Courier New`, `Consolas`)
> - Dark background with light text (black/gray theme with green/blue accents)
> - Terminal-like aesthetic
> - Clear section headers and code blocks
> - Professional layout using embedded CSS (no external dependencies)
> - Include header/footer with tool name and page numbers (if applicable)

> #### 5. **Output**
> - Save the HTML report as: `OTG-SESS-006_Logout_Functionality_Report.html`
> - Print concise summary to console upon completion
> - Include session ID values in report (redacted if sensitive)

> #### 6. **Additional Notes**
> - Include comments in the script for clarity
> - Make the script configurable via variables at the top (URLs, credentials, etc.)
> - Ensure compatibility with Python 3.7+
> - Handle common exceptions (e.g., connection refused, login failure)
> - The script should not require external tools beyond `requests` and `beautifulsoup4`

> Return only the **complete Python script**, fully self-contained, with embedded HTML template for the report. No markdown, no explanation—just the code.

---

## Deliverable

The AI agent should return a `.py` file that satisfies the above prompt. This `.md` file serves as the instruction set for generating that script.

You may now proceed to generate the Python script based on this prompt.