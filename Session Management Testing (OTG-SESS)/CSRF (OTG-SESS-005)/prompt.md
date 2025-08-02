# AI Coding Agent Prompt: CSRF Test Script for DVWA (OTG-SESS-005)

## Objective

Create a Python-based automated testing script that evaluates **Cross-Site Request Forgery (CSRF)** vulnerabilities in Damn Vulnerable Web Application (DVWA) running on a local XAMPP server (`http://localhost/dvwa`). The script should specifically target **OTG-SESS-005 - Testing for Cross Site Request Forgery** as defined in the OWASP Testing Guide.

Upon completion, the script must generate a professional, well-structured, and visually appealing **HTML report** in the style of **OSCP (Offensive Security Certified Professional)** and **OWASP** documentation standards.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs automated testing for **Cross-Site Request Forgery (CSRF) (OTG-SESS-005)** on **DVWA (Damn Vulnerable Web Application)** hosted locally via **XAMPP** at `http://localhost/dvwa`.

> ### Requirements

> #### 1. **Target Environment**
> - DVWA is running on `http://localhost/dvwa`
> - The script assumes DVWA is properly configured and accessible
> - Default credentials: `admin:password` (used only for login simulation)
> - Security level: test across **Low**, **Medium**, and **High** levels if possible
> - Script must work on HTTP (no HTTPS required)

> #### 2. **Test Scope – OTG-SESS-005**
> The script must:
> - Log in to DVWA with valid credentials
> - Identify forms that perform state-changing operations (e.g., password change, security level change)
> - Test whether these forms are protected by anti-CSRF tokens
> - Attempt to perform state-changing actions **without** or with **reused** CSRF tokens
> - Test if requests can be forged from external origins (simulated)
> - Verify if the application implements proper CSRF protections:
>   - Presence of unique, unpredictable CSRF tokens
>   - Token validation on the server side
>   - Proper token regeneration
>   - Use of SameSite cookie attributes (if applicable)
> - Determine vulnerability based on successful forged requests

> #### 3. **Script Functionality**
> - Use `requests` and `BeautifulSoup` (or equivalent) to interact with DVWA
> - Handle session management properly
> - Extract and analyze forms that perform state-changing actions
> - Test CSRF protection by:
>   - Omitting CSRF tokens
>   - Reusing old tokens
>   - Using invalid tokens
> - Support testing at different security levels
> - Log all requests and responses for analysis
> - Output structured findings (VULNERABLE/NOT VULNERABLE) for each test case
> - Be non-destructive (avoid changing passwords to unknown values)

> #### 4. **Report Generation**
> After testing, generate a **standalone HTML report** with:
> - **Title**: "CSRF Test – OTG-SESS-005"
> - **Target**: `http://localhost/dvwa`
> - **Test Date & Time**
> - **Executive Summary**
> - **Test Details**:
>   - Methodology (step-by-step testing approach)
>   - List of tested endpoints (forms)
>   - Request/Response pairs for successful attacks (if any)
>   - Analysis of CSRF token implementation
>   - Findings with clear VULNERABLE/NOT VULNERABLE status
> - **Risk Rating**: High (if vulnerable), otherwise Low
> - **Remediation Recommendations** (e.g., "Implement unique CSRF tokens", "Validate tokens server-side")
> - **References**: OWASP CSRF, OTG-SESS-005, CWE-352, CVE examples
> 
> The report must follow **OSCP-style formatting**:
> - Monospace font (e.g., `Courier New`, `Consolas`)
> - Dark background with light text (black/gray theme with green/blue accents)
> - Terminal-like aesthetic
> - Clear section headers and code blocks
> - Professional layout using embedded CSS (no external dependencies)
> - Include header/footer with tool name and page numbers (if applicable)

> #### 5. **Output**
> - Save the HTML report as: `OTG-SESS-005_CSRF_Report.html`
> - Print concise summary to console upon completion
> - Include request examples in report (with sensitive data redacted)

> #### 6. **Additional Notes**
> - Include comments in the script for clarity
> - Make the script configurable via variables at the top (URLs, credentials, endpoints, etc.)
> - Ensure compatibility with Python 3.7+
> - Handle common exceptions (e.g., connection refused, login failure)
> - The script should not require external tools beyond `requests` and `beautifulsoup4`

> Return only the **complete Python script**, fully self-contained, with embedded HTML template for the report. No markdown, no explanation—just the code.

---

## Deliverable

The AI agent should return a `.py` file that satisfies the above prompt. This `.md` file serves as the instruction set for generating that script.

You may now proceed to generate the Python script based on this prompt.