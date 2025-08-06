# AI Coding Agent Prompt: DVWA Test HTTP Methods (OTG-CONFIG-006)

## Objective

Create a Python script that automates testing of **HTTP methods** on a locally running **Damn Vulnerable Web Application (DVWA)** instance via **XAMPP on localhost**. The script must identify enabled/disabled HTTP methods, test for insecure method implementations, and generate a professional **OWASP/OSCP-style penetration testing report** in a standalone, well-designed HTML file.

---

## Prompt for AI Coding Agent

> You are a skilled cybersecurity automation engineer tasked with creating a comprehensive security testing tool for DVWA (Damn Vulnerable Web Application) running on a local XAMPP server (`http://localhost/dvwa`). Your goal is to assess the application's handling of HTTP methods in accordance with **OWASP Testing Guide v4 - OTG-CONFIG-006: Test HTTP Methods**.

> Develop a **Python script** that:
>
> 1. **Connects to DVWA** at `http://localhost/dvwa` and logs in using default credentials (`admin:password`) via session-based authentication (handle CSRF tokens if present).
> 2. **Tests for enabled HTTP methods** on key endpoints including:
>    - `/dvwa/`
>    - `/dvwa/login.php`
>    - `/dvwa/vulnerabilities/`
>    - `/dvwa/security.php`
>    - `/dvwa/logout.php`
>    - `/dvwa/setup.php`
> 3. **Sends requests using various HTTP methods**:
>    - Standard methods: GET, POST, HEAD, OPTIONS
>    - Less common methods: PUT, DELETE, TRACE, CONNECT, PATCH
>    - Unsafe methods: PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK
> 4. **Analyzes responses** to determine:
>    - Which methods are allowed (200, 201, 204)
>    - Which methods are denied (403, 405)
>    - Response headers (especially Allow and Public)
>    - Potential security issues (e.g., TRACE method enabled, unsafe methods allowed)
> 5. **Tests for HTTP method tampering vulnerabilities** by:
>    - Sending POST requests as GET and vice versa
>    - Testing if form submissions work with different methods
>    - Checking for insecure file upload methods
> 6. **Performs TRACE method testing** for potential Cross-Site Tracing (XST) vulnerabilities
> 7. **Generates a detailed HTML report** titled `DVWA_HTTP_Methods_Report.html` styled in **OSCP/OWASP penetration testing format**, including:
>    - Executive Summary
>    - Test Overview (OWASP OTG-CONFIG-006)
>    - Methodology
>    - Findings Table (Endpoint, Method, Status, Risk Level)
>    - Detailed Findings with request/response snippets
>    - Remediation Recommendations
>    - Conclusion
> 8. The HTML report must be **visually clean**, use a monospace font for code, color-coded risk indicators (Red/Amber/Green), and include a pentesting theme consistent with OSCP report aesthetics (e.g., dark headers, professional layout).
> 9. The script must be **non-destructive** — it should only perform read operations and safe method testing.
> 10. Include error handling for network issues, authentication failures, and missing paths.
> 11. Output verbose logging to console during execution.
> 12. Ensure the script can be run with a simple command: `python dvwa_http_method_test.py`
> 13. The script should automatically detect and handle DVWA’s CSRF tokens during login.
> 14. Include analysis of the `Allow` and `Public` headers in responses to determine supported methods.

> Ensure the script is modular, well-commented, and includes a `requirements.txt` suggestion (e.g., `requests`, `BeautifulSoup4`).

> At the end of execution, print:  
> `[+] Report generated: ./reports/DVWA_HTTP_Methods_Report.html`

---

## Expected Output

- `dvwa_http_method_test.py` – The main Python testing script.
- `reports/DVWA_HTTP_Methods_Report.html` – Styled HTML report in OSCP format.

---

## Notes

- Assume DVWA is configured at `http://localhost/dvwa` and XAMPP is running Apache/MySQL.
- Security level in DVWA can be set to "Low" for testing purposes.
- The HTML report should be self-contained (inline CSS/JS) for portability.
- Focus on identifying dangerous methods like TRACE, PUT, DELETE that could be exploited.
- Test both authenticated and unauthenticated endpoints.

---

## Usage Example

```bash
python dvwa_http_method_test.py