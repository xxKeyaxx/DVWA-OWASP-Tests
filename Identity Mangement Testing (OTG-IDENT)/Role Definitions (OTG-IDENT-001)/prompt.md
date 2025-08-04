# AI Coding Agent Prompt: DVWA Role Definitions Security Test Script & OSCP-Style HTML Report

## Objective

Create a comprehensive automated script that tests **Role Definitions (OTG-IDENT-001)** on a **DVWA (Damn Vulnerable Web Application)** instance running locally via **XAMPP on `localhost`**. The script should evaluate how well the application enforces role-based access control (RBAC), identify privilege escalation opportunities, and generate a professional, well-structured **OWASP/OSCP-style security report** in **HTML format**.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation expert tasked with developing a Python-based security testing script for the **OTG-IDENT-001 (Testing Role Definitions)** control from the **OWASP Testing Guide v4**. The target is **DVWA v1.9 or lower (PHP/MySQL)** hosted on a local XAMPP server at `http://localhost/dvwa/`.

> Your goal is to:
>
> 1. **Automate the login process** using known default credentials (e.g., `admin:password`) and handle DVWA's security token (anti-CSRF).
> 2. **Enumerate available user roles** (e.g., admin, user) and simulate access attempts to restricted pages or functionalities based on assumed roles.
> 3. **Test for improper role enforcement** by:
>    - Attempting to access admin-only pages (e.g., `http://localhost/dvwa/security.php`, `http://localhost/dvwa/users.php`) as a low-privileged user.
>    - Testing for **direct object reference (IDOR)** or **URL manipulation** to access unauthorized functionality.
>    - Checking if role changes can be forced via parameters (e.g., `role=admin`, `user_level=1` in requests).
> 4. **Log all HTTP responses**, status codes, and observed behaviors for analysis.
> 5. **Generate a detailed security report** in **HTML format** styled in the **OSCP/OWASP report aesthetic**, including:
>    - Executive Summary
>    - Test Details (OTG-IDENT-001)
>    - Methodology
>    - Observations & Evidence (with screenshots or request/response snippets)
>    - Risk Rating (e.g., High/Medium/Low)
>    - Recommendations
>    - References (OWASP, CWE, etc.)
>
> The HTML report must:
> - Use a clean, monospace font layout reminiscent of OSCP exam reports.
> - Include a dark theme with green/white contrast (inspired by terminal aesthetics).
> - Be self-contained (inline CSS, no external dependencies).
> - Feature a header with "Security Assessment Report", target (`localhost/dvwa`), date, and test ID: `OTG-IDENT-001`.
> - Include a table of findings with **Vulnerability**, **Endpoint**, **Evidence**, and **Severity**.
> - Be saved as `OTG-IDENT-001_Report.html` in the current directory.
>
> Use Python with `requests`, `BeautifulSoup`, and `os` modules. Handle sessions, cookies, and CSRF tokens properly. Assume DVWA is configured with `allow_url_fopen = Off` and `allow_url_include = Off`, but is otherwise default.
>
> Output only the complete Python script. Do not include explanations.

---

## Expected Output

A single Python script (`test_role_definitions.py`) that:
- Runs the security test against DVWA on `localhost`.
- Produces a detailed `OTG-IDENT-001_Report.html` in OSCP report style.
- Is safe, non-destructive, and logs findings clearly.

---

## Notes for Implementation

- Ensure the script checks if DVWA is reachable before proceeding.
- Simulate both low-privilege and high-privilege access attempts.
- The HTML report should reflect real test results, even if no vulnerabilities are found.
- Use proper error handling and session cleanup.
- This script is intended for educational and ethical testing purposes only.

---