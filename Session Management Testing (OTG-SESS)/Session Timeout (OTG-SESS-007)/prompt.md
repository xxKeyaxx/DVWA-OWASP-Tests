# AI Coding Agent Prompt: Session Timeout Test Script for DVWA (OTG-SESS-007)

## Objective

Create a Python-based automated testing script that evaluates **Session Timeout** functionality in Damn Vulnerable Web Application (DVWA) running on a local XAMPP server (`http://localhost/dvwa`). The script should specifically target **OTG-SESS-007 - Testing for Session Timeout** as defined in the OWASP Testing Guide.

Upon completion, the script must generate a professional, well-structured, and visually appealing **HTML report** in the style of **OSCP (Offensive Security Certified Professional)** and **OWASP** documentation standards.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs automated testing for **Session Timeout (OTG-SESS-007)** on **DVWA (Damn Vulnerable Web Application)** hosted locally via **XAMPP** at `http://localhost/dvwa`.

> ### Requirements

> #### 1. **Target Environment**
> - DVWA is running on `http://localhost/dvwa`
> - The script assumes DVWA is properly configured and accessible
> - Default credentials: `admin:password` (used only for login simulation)
> - Security level: test at **Low**, **Medium**, and **High** levels
> - Script must work on HTTP (no HTTPS required)

> #### 2. **Test Scope – OTG-SESS-007**
> The script must:
> - Log in to DVWA with valid credentials
> - Test session timeout by:
>   - Measuring the actual timeout duration
>   - Verifying if sessions expire after a period of inactivity
>   - Checking if expired sessions are properly invalidated
>   - Testing if users are redirected to login page after timeout
>   - Validating that old session tokens cannot be reused
>   - Testing session persistence across browser restarts (if applicable)
> - Test at different security levels to identify configuration differences
> - Evaluate if timeout values meet security best practices
> - Check for proper session cleanup on the server side

> #### 3. **Script Functionality**
> - Use `requests` and `BeautifulSoup` (or equivalent) to interact with DVWA
> - Handle CSRF tokens where necessary
> - Implement a time-based testing approach:
>   1. Login and record initial session state
>   2. Wait for specified timeout periods
>   3. Attempt to access protected resources
>   4. Verify session status
> - Support configurable timeout intervals (e.g., 1, 5, 10, 15 minutes)
> - Test both short and long idle periods
> - Log all timestamps, session states, and HTTP responses
> - Output structured findings with elapsed times and status changes
> - Be non-destructive and safe for local testing

> #### 4. **Report Generation**
> After testing, generate a **standalone HTML report** with:
> - **Title**: "Session Timeout Test – OTG-SESS-007"
> - **Target**: `http://localhost/dvwa`
> - **Test Date & Time**
> - **Executive Summary**
> - **Test Details**:
>   - Methodology (testing approach and intervals)
>   - Session timeout measurements for each security level
>   - Timeline of session state changes
>   - HTTP request/response analysis
>   - Evidence of proper or improper session expiration
>   - Findings with clear Pass/Fail status
> - **Risk Rating**: High (if timeout is too long or ineffective), otherwise Medium/Low
> - **Recommended Timeout Values** based on best practices
> - **Remediation Recommendations** (e.g., "Implement shorter timeout periods", "Properly invalidate expired sessions")
> - **References**: OWASP Session Timeout, OTG-SESS-007, CWE-613 (Insufficient Session Expiration)
> 
> The report must follow **OSCP-style formatting**:
> - Monospace font (e.g., `Courier New`, `Consolas`)
> - Dark background with light text (black/gray theme with green/blue accents)
> - Terminal-like aesthetic
> - Clear section headers and code blocks
> - Professional layout using embedded CSS (no external dependencies)
> - Include header/footer with tool name and page numbers (if applicable)

> #### 5. **Output**
> - Save the HTML report as: `OTG-SESS-007_Session_Timeout_Report.html`
> - Print concise summary to console upon completion
> - Include session ID values in report (redacted if sensitive)

> #### 6. **Additional Notes**
> - Include comments in the script for clarity
> - Make the script configurable via variables at the top (URLs, credentials, timeout intervals, etc.)
> - Ensure compatibility with Python 3.7+
> - Handle common exceptions (e.g., connection refused, login failure)
> - The script should not require external tools beyond `requests` and `beautifulsoup4`

> Return only the **complete Python script**, fully self-contained, with embedded HTML template for the report. No markdown, no explanation—just the code.

---

## Deliverable

The AI agent should return a `.py` file that satisfies the above prompt. This `.md` file serves as the instruction set for generating that script.

You may now proceed to generate the Python script based on this prompt.