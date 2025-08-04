# AI Coding Agent Prompt: DVWA Weak/Unenforced Username Policy Test (OTG-IDENT-005)

## Objective

Create a Python-based security testing script that evaluates **Weak or Unenforced Username Policy (OTG-IDENT-005)** on a **DVWA (Damn Vulnerable Web Application)** instance running locally via **XAMPP on `http://localhost/dvwa/`**. The script should analyze username creation and validation mechanisms, identify policy weaknesses, and generate a professional, **OWASP/OSCP-style HTML report** with findings.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation expert tasked with developing a Python script to perform **OTG-IDENT-005 (Testing for Weak or Unenforced Username Policy)** in accordance with the **OWASP Testing Guide v4**. The target is **DVWA v1.9 or lower** hosted on a local XAMPP server at `http://localhost/dvwa/`.

> Your goal is to:
>
> 1. **Analyze the user creation/registration process** in DVWA to determine if username policies are enforced.
> 2. **Test username validation** by attempting to create or interact with usernames containing:
>    - Special characters (e.g., `<`, `>`, `&`, `'`, `"`, `/`, `\`, `;`, `(`, `)`)
>    - SQL injection patterns (e.g., `' OR '1'='1`, `'; DROP TABLE`)
>    - XSS payloads (e.g., `<script>alert(1)</script>`)
>    - Excessively long usernames (over 50 characters)
>    - Whitespace and Unicode characters
>    - Common predictable patterns (e.g., `admin`, `administrator`, `test123`)
> 3. **Evaluate username uniqueness enforcement** - can duplicate usernames be created?
> 4. **Test username enumeration resistance** - does the application reveal whether a username exists during creation?
> 5. **Assess username case sensitivity** - can `Admin` and `admin` both be used?
> 6. **Generate a detailed security report** in **HTML format** styled in the **OSCP/penetration testing report aesthetic**, including:
>    - Executive Summary
>    - Test Details (OTG-IDENT-005)
>    - Methodology
>    - Identified Weaknesses with Evidence
>    - Risk Rating (High/Medium/Low)
>    - Recommendations for policy improvement
>    - References (OWASP, CWE, etc.)
>
> The HTML report must:
> - Use a **dark theme with monospace font** (e.g., 'Courier New') for terminal-like appearance.
> - Feature **color-coded severity indicators** (red for High, yellow for Medium, green for Low).
> - Be **self-contained** with inline CSS (no external resources).
> - Include a header with: "OWASP Security Assessment Report", target URL, test ID `OTG-IDENT-005`, and current date/time.
> - Contain a **findings table** with columns: Vulnerability, Username Tested, Evidence, Severity.
> - Save as `OTG-IDENT-005_Report.html` in the current directory.
>
> Use Python with `requests`, `BeautifulSoup`, and `re` modules. Handle CSRF tokens properly. Assume DVWA is in **low security mode**.
>
> The script should:
> - First check if user creation functionality exists in DVWA
> - Test various username policy aspects systematically
> - Log all requests and responses for analysis
> - Generate the report even if no vulnerabilities are found
> - Include ethical use disclaimers in comments
>
> **Note**: DVWA may not have a traditional user registration system, so focus on:
> - User management functionality (`users.php`)
> - Any form inputs that accept usernames
> - Login page behavior with special character usernames
> - Analysis of existing usernames in the application
>
> Output only the complete Python script. Do not include explanations.

---

## Expected Output

A single executable Python script (`test_username_policy.py`) that:
- Connects to DVWA on `localhost`
- Tests for weak/unenforced username policies
- Generates a well-formatted `OTG-IDENT-005_Report.html` in OSCP style
- Is safe, efficient, and follows ethical testing practices

---

## Notes for Implementation

- The script should attempt to identify any user creation/modification functionality
- Test both input validation and output encoding for usernames
- Check for XSS and SQL injection vulnerabilities through username fields
- Evaluate predictability of usernames (e.g., sequential numbering)
- The report should reflect real test results with proper evidence
- Add error handling for network issues and DVWA availability
- Emphasize that this is for learning and authorized testing only

---