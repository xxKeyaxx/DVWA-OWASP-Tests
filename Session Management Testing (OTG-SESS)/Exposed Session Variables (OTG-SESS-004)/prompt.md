# AI Coding Agent Prompt: Exposed Session Variables Test Script for DVWA (OTG-SESS-004)

## Objective

Create a Python-based automated testing script that evaluates **Exposed Session Variables** in Damn Vulnerable Web Application (DVWA) running on a local XAMPP server (`http://localhost/dvwa`). The script should specifically target **OTG-SESS-004 - Testing for Exposed Session Variables** as defined in the OWASP Testing Guide.

Upon completion, the script must generate a professional, well-structured, and visually appealing **HTML report** in the style of **OSCP (Offensive Security Certified Professional)** and **OWASP** documentation standards.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs automated testing for **Exposed Session Variables (OTG-SESS-004)** on **DVWA (Damn Vulnerable Web Application)** hosted locally via **XAMPP** at `http://localhost/dvwa`.

> ### Requirements

> #### 1. **Target Environment**
> - DVWA is running on `http://localhost/dvwa`
> - The script assumes DVWA is properly configured and accessible
> - Default credentials: `admin:password` (used only for login simulation)
> - Security level: set to **Low** or **Medium** for test consistency
> - Script must work on HTTP (no HTTPS required)

> #### 2. **Test Scope – OTG-SESS-004**
> The script must:
> - Log in to DVWA with valid credentials
> - Navigate through multiple application pages (e.g., Home, User Info, Security, etc.)
> - Analyze HTTP responses for **session-related variables exposed in client-side code**, including:
>   - Session tokens or IDs in HTML source (e.g., hidden form fields)
>   - Session data in JavaScript variables
>   - Sensitive session information in URL parameters
>   - Session data in meta tags, comments, or client-side storage references
>   - Any user-specific data exposed unnecessarily
> - Test for **insecure transmission** of session variables (e.g., via GET parameters)
> - Identify if session-sensitive data is unnecessarily exposed to the client

> #### 3. **Script Functionality**
> - Use `requests` and `BeautifulSoup` (or equivalent) to interact with DVWA
> - Handle CSRF tokens where necessary (e.g., login, security settings)
> - Parse HTML, JavaScript, and response bodies for session-related keywords:
>   - `session`, `token`, `user_token`, `PHPSESSID`, `auth`, `login`, `password`, `id`, `role`, `level`
> - Check URLs for session data in query parameters
> - Maintain session throughout the test
> - Output structured findings with evidence (code snippets, locations)
> - Be non-destructive and safe for local testing

> #### 4. **Report Generation**
> After testing, generate a **standalone HTML report** with:
> - **Title**: "Exposed Session Variables Test – OTG-SESS-004"
> - **Target**: `http://localhost/dvwa`
> - **Test Date & Time**
> - **Executive Summary**
> - **Test Details**:
>   - Methodology (pages tested, techniques used)
>   - List of exposed session variables with context
>   - Code snippets showing exposure
>   - Location (URL, element type, line reference)
>   - Risk assessment per finding
>   - Evidence of vulnerability
> - **Risk Rating**: Medium/High (based on exposure level)
> - **Remediation Recommendations** (e.g., "Avoid passing session data in URLs", "Don't expose tokens in JS variables")
> - **References**: OWASP Session Management, OTG-SESS-004, CWE-200 (Information Exposure)
> 
> The report must follow **OSCP-style formatting**:
> - Monospace font (e.g., `Courier New`, `Consolas`)
> - Dark background with light text (black/gray theme with green/blue accents)
> - Terminal-like aesthetic
> - Clear section headers and code blocks
> - Professional layout using embedded CSS (no external dependencies)
> - Include header/footer with tool name and page numbers (if applicable)

> #### 5. **Output**
> - Save the HTML report as: `OTG-SESS-004_Exposed_Session_Variables_Report.html`
> - Print concise summary to console upon completion
> - Include redacted values if sensitive data is found

> #### 6. **Additional Notes**
> - Include comments in the script for clarity
> - Make the script configurable via variables at the top (URLs, credentials, keywords, etc.)
> - Ensure compatibility with Python 3.7+
> - Handle common exceptions (e.g., connection refused, login failure)
> - The script should not require external tools beyond `requests` and `beautifulsoup4`

> Return only the **complete Python script**, fully self-contained, with embedded HTML template for the report. No markdown, no explanation—just the code.

---

## Deliverable

The AI agent should return a `.py` file that satisfies the above prompt. This `.md` file serves as the instruction set for generating that script.

You may now proceed to generate the Python script based on this prompt.