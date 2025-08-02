# AI Coding Agent Prompt: Cookie Attributes Test Script for DVWA (OTG-SESS-002)

## Objective

Create a Python-based automated testing script that evaluates the **security attributes of cookies** used by Damn Vulnerable Web Application (DVWA) running on a local XAMPP server (`http://localhost/dvwa`). The script should specifically target **OTG-SESS-002 - Testing for Cookies Attributes** as defined in the OWASP Testing Guide.

Upon completion, the script must generate a professional, well-structured, and visually appealing **HTML report** in the style of **OSCP (Offensive Security Certified Professional)** and **OWASP** documentation standards.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs automated testing for **Cookie Attributes (OTG-SESS-002)** on **DVWA (Damn Vulnerable Web Application)** hosted locally via **XAMPP** at `http://localhost/dvwa`.

> ### Requirements

> #### 1. **Target Environment**
> - DVWA is running on `http://localhost/dvwa`
> - The script assumes DVWA is configured and accessible
> - Default credentials: `admin:password` (used only for login simulation)
> - Security level: set to **Low** for test consistency (optional: allow override via config)

> #### 2. **Test Scope – OTG-SESS-002**
> The script must:
> - Log in to DVWA to obtain session cookies
> - Analyze all cookies set by the application for the following attributes:
>   - **Secure**: Ensures cookie is only sent over HTTPS (should be flagged as missing on HTTP)
>   - **HttpOnly**: Prevents client-side script access (mitigates XSS)
>   - **SameSite**: Protects against CSRF attacks (values: Strict, Lax, or None)
>   - **Domain** and **Path**: Validate appropriate scoping
>   - **Expires/Max-Age**: Check for persistent vs. session cookies
> - Test for **Session Cookie Exposure** in URLs or logs (if applicable)
> - Evaluate the risk level based on missing attributes
> - Perform checks for multiple endpoints if necessary (login, dashboard, logout)

> #### 3. **Script Functionality**
> - Use `requests` and `BeautifulSoup` (or equivalent) to interact with DVWA
> - Handle CSRF tokens where necessary (e.g., login form)
> - Extract and parse all cookies received during the session
> - Output structured findings (pass/fail) for each cookie attribute test
> - Be non-destructive (avoid brute-force or DoS)

> #### 4. **Report Generation**
> After testing, generate a **standalone HTML report** with:
> - **Title**: "Cookie Attributes Test – OTG-SESS-002"
> - **Target**: `http://localhost/dvwa`
> - **Test Date & Time**
> - **Executive Summary**
> - **Test Details**:
>   - List of cookies analyzed
>   - Table of attributes for each cookie (attribute, value, expected, status)
>   - Risk assessment per missing attribute
>   - Methodology
>   - Findings (Pass/Fail with explanation)
> - **Risk Rating**: Medium/High (based on OWASP Risk Rating)
> - **Remediation Recommendations** (e.g., "Add HttpOnly flag", "Set SameSite=Lax")
> - **References**: OWASP Secure Cookie Attributes, OTG-SESS-002, CWE-1004, CWE-79
> 
> The report must follow **OSCP-style formatting**:
> - Monospace font (e.g., `Courier New`, `Consolas`)
> - Dark background with light text (optional: green/blue accent)
> - Terminal-like aesthetic
> - Clear section headers and code blocks
> - Professional layout using embedded CSS (no external dependencies)
> - Include a simple header/footer with tool name and page numbers (if applicable)

> #### 5. **Output**
> - Save the HTML report as: `OTG-SESS-002_Cookie_Attributes_Report.html`
> - Print summary to console upon completion

> #### 6. **Additional Notes**
> - Include comments in the script for clarity
> - Make the script configurable (e.g., via variables at the top)
> - Ensure compatibility with Python 3.7+
> - Handle common exceptions (e.g., connection refused, login failure)
> - The script should not require external tools beyond standard libraries and `requests`, `beautifulsoup4`

> Return only the **complete Python script**, fully self-contained, with embedded HTML template for the report. No markdown, no explanation—just the code.

---

## Deliverable

The AI agent should return a `.py` file that satisfies the above prompt. This `.md` file serves as the instruction set for generating that script.

You may now proceed to generate the Python script based on this prompt.