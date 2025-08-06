# AI Coding Agent Prompt: DVWA File Extension Handling Test (OTG-CONFIG-003)

## Objective

Create a Python script that automates testing of file extension handling for sensitive information on a locally running **Damn Vulnerable Web Application (DVWA)** instance via **XAMPP on localhost**. The script must evaluate whether the server improperly handles or serves sensitive file types (e.g., `.php`, `.env`, `.bak`, `.sql`, `.config`, etc.) that could expose configuration or source code.

After testing, generate a professional, **OWASP/OSCP-style penetration testing report** in a standalone, well-designed **HTML file** that follows OSCP reporting standards in structure, formatting, and tone.

---

## Prompt for AI Coding Agent

> You are a skilled cybersecurity automation engineer tasked with creating a comprehensive security testing tool for DVWA (Damn Vulnerable Web Application) running on a local XAMPP server (`http://localhost/dvwa`). Your goal is to assess the application's handling of file extensions in the context of **OTG-CONFIG-003: Test File Extension Handling for Sensitive Information**, as defined by the OWASP Testing Guide.

> Develop a **Python script** that:
>
> 1. **Connects to DVWA** at `http://localhost/dvwa` and logs in using default credentials (`admin:password`) via session-based authentication (handle CSRF tokens if present).
> 2. Identifies accessible directories in DVWA (e.g., `/hackable/uploads/`, `/includes/`, `/backup/`, etc.) that may contain sensitive files.
> 3. Tests for the presence and **insecure exposure** of sensitive files with dangerous extensions such as:
>    - `.php`, `.php~`, `.php.bak`, `.php.save`, `.php.old`
>    - `.env`, `.env.local`, `.git`, `.htaccess`
>    - `.sql`, `.bak`, `.backup`, `.zip`, `.config`
>    - `.log`, `.yml`, `.yaml`, `.json`
> 4. For each target file, attempts to access it directly via HTTP and records:
>    - HTTP status code
>    - Whether content is returned (e.g., source code disclosure)
>    - MIME type served
>    - Any sensitive data exposure (e.g., DB credentials, tokens)
> 5. Uses a **configurable wordlist** (included as a list in the script or loaded from a `.txt` file) for file names and extensions.
> 6. Logs all requests and responses for analysis.
> 7. **Generates a detailed HTML report** titled `DVWA_File_Extension_Test_Report.html` styled in **OSCP/OWASP penetration testing format**, including:
>    - Executive Summary
>    - Test Overview (OWASP OTG-CONFIG-003)
>    - Methodology
>    - Findings Table (Vulnerability Name, Location, Risk Level, Evidence)
>    - Detailed Findings with request/response snippets
>    - Remediation Recommendations
>    - Conclusion
> 8. The HTML report must be **visually clean**, use a monospace font for code, color-coded risk indicators (Red/Amber/Green), and include the DVWA logo or a pentesting theme consistent with OSCP report aesthetics.
> 9. The script must be **non-destructive** — it should only perform read/access operations.
> 10. Include error handling for network issues, authentication failures, and missing paths.
> 11. Output verbose logging to console during execution and save raw responses in a `/logs` directory if needed.

> Ensure the script is modular, well-commented, and includes a `requirements.txt` suggestion (e.g., `requests`, `BeautifulSoup4`).

> At the end of execution, print:  
> `[+] Report generated: ./reports/DVWA_File_Extension_Test_Report.html`

---

## Expected Output

- `dvwa_file_extension_test.py` – The main Python testing script.
- `sensitive_files.txt` – Wordlist of files/extensions to test.
- `reports/DVWA_File_Extension_Test_Report.html` – Styled HTML report in OSCP format.

---

## Notes

- Assume DVWA is configured at `http://localhost/dvwa` and XAMPP is running Apache/MySQL.
- Security level in DVWA can be set to "Low" for testing purposes.
- The script should automatically detect and handle DVWA’s CSRF tokens during login.
- The HTML report should be self-contained (inline CSS/JS) for portability.

---

## Usage Example

```bash
python dvwa_file_extension_test.py