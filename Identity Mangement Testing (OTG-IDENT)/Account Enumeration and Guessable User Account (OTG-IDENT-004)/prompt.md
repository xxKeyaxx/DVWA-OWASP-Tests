# AI Coding Agent Prompt: DVWA Account Enumeration & Guessable Accounts Test (OTG-IDENT-004)

## Objective

Create a Python-based security testing script that automates the detection of **Account Enumeration and Guessable User Accounts (OTG-IDENT-004)** on a **DVWA (Damn Vulnerable Web Application)** instance running locally via **XAMPP on `http://localhost/dvwa/`**. The script should identify user accounts through various enumeration techniques and assess the guessability of credentials, then generate a professional, **OSCP/OWASP-style HTML report** with findings.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation expert tasked with developing a Python script to perform **OTG-IDENT-004 (Testing for Account Enumeration and Guessable User Account)** in accordance with the **OWASP Testing Guide v4**. The target is **DVWA v1.9 or lower** hosted on a local XAMPP server at `http://localhost/dvwa/`.

> Your goal is to:
>
> 1. **Automate login attempts** using a predefined list of common usernames (e.g., `admin`, `gordonb`, `pablo`, `smithy`) and weak passwords to test for guessable accounts.
> 2. **Detect account enumeration vulnerabilities** by analyzing differences in application responses during login (e.g., "Login failed" vs. "User doesn't exist").
> 3. **Test the login page (`login.php`)** for response inconsistencies that leak valid usernames.
> 4. **Log all HTTP responses, status codes, and timing differences** to identify enumeration vectors.
> 5. **Generate a detailed security report** in **HTML format** styled in the **OSCP/penetration testing report aesthetic**, including:
>    - Executive Summary
>    - Test Details (OTG-IDENT-004)
>    - Methodology
>    - Observed Behavior & Evidence (with response snippets)
>    - Identified Valid Accounts
>    - Risk Rating (High/Medium/Low)
>    - Recommendations for mitigation
>    - References (OWASP, CWE, etc.)
>
> The HTML report must:
> - Use a **dark theme with monospace font** (e.g., 'Courier New') for terminal-like appearance.
> - Feature **color-coded severity indicators** (red for High, yellow for Medium, green for Low).
> - Be **self-contained** with inline CSS (no external resources).
> - Include a header with: "OWASP Security Assessment Report", target URL, test ID `OTG-IDENT-004`, and current date/time.
> - Contain a **findings table** with columns: Vulnerability, Username, Evidence, Severity.
> - Save as `OTG-IDENT-004_Report.html` in the current directory.
>
> Use Python with `requests`, `BeautifulSoup`, and `time` modules. Handle CSRF tokens properly during login attempts. Assume DVWA is in **low security mode**.
>
> The script should:
> - First test for **account enumeration** by submitting invalid usernames and analyzing responses.
> - Then perform **limited brute-force/guessing** on common usernames with a small password list (only for educational purposes).
> - Avoid excessive requests to prevent system instability.
> - Output findings clearly and generate the report even if no vulnerabilities are found.
>
> **Important**: This script is for educational and authorized testing only. Include ethical use disclaimers in comments.
>
> Output only the complete Python script. Do not include explanations.

---

## Expected Output

A single executable Python script (`test_account_enumeration.py`) that:
- Connects to DVWA on `localhost`
- Tests for account enumeration vulnerabilities
- Identifies valid/guessable accounts
- Generates a well-formatted `OTG-IDENT-004_Report.html` in OSCP style
- Is safe, efficient, and follows ethical testing practices

---

## Notes for Implementation

- The script must detect subtle differences in error messages (e.g., "Username unknown" vs. "Incorrect password").
- Include a small, responsible wordlist (5-10 common usernames and passwords).
- Handle DVWA's CSRF token (`user_token`) in login requests.
- The report should reflect real test results with proper evidence.
- Add error handling for network issues and DVWA availability.
- Emphasize that this is for learning and authorized testing only.

---