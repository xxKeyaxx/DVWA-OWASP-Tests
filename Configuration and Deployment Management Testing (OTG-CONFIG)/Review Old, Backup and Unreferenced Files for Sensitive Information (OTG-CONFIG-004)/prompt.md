# AI Coding Agent Prompt: DVWA Review of Old, Backup & Unreferenced Files (OTG-CONFIG-004)

## Objective

Create a Python script that automates the detection and analysis of **old, backup, and unreferenced files** for sensitive information on a locally running **Damn Vulnerable Web Application (DVWA)** instance via **XAMPP on localhost**. The script must identify files with common backup extensions, temporary names, and orphaned files not linked in the application, and generate a professional **OWASP/OSCP-style penetration testing report** in a standalone, well-designed HTML file.

---

## Prompt for AI Coding Agent

> You are a skilled cybersecurity automation engineer tasked with creating a comprehensive security testing tool for DVWA (Damn Vulnerable Web Application) running on a local XAMPP server (`http://localhost/dvwa`). Your goal is to assess the application's exposure of obsolete or forgotten files that could leak sensitive information, in accordance with **OWASP Testing Guide v4 - OTG-CONFIG-004: Review Old, Backup and Unreferenced Files for Sensitive Information**.

> Develop a **Python script** that:
>
> 1. **Connects to DVWA** at `http://localhost/dvwa` and logs in using default credentials (`admin:password`) via session-based authentication (handle CSRF tokens if present).
> 2. **Discovers accessible directories** in DVWA (e.g., `/includes/`, `/uploads/`, `/backup/`, `/config/`) that may contain old or backup files.
> 3. **Scans for files with backup/temporary extensions**, such as:
>    - `.bak`, `.backup`, `.old`, `.orig`, `.tmp`, `.temp`, `.save`, `.swp`
>    - `~`, `.zip`, `.tar`, `.tar.gz`, `.rar`, `.bak.sql`, `.sql.bak`
>    - `.php~`, `.inc.bak`, `.config.old`, `.gitignore.bak`
> 4. **Identifies unreferenced files** by:
>    - Crawling the site to find linked files
>    - Comparing against discovered files to detect "orphaned" files
>    - Flagging files not referenced in HTML, JS, or CSS
> 5. For each suspicious file, attempts to access it and records:
>    - HTTP status code
>    - Whether source code or sensitive data is exposed
>    - File size and content type
>    - Indicators of sensitive content (DB credentials, passwords, API keys)
> 6. Uses a **configurable wordlist** of common backup filenames (e.g., `config.bak`, `database.sql.bak`, `settings.inc.bak`) and extensions.
> 7. **Generates a detailed HTML report** titled `DVWA_Backup_Files_Report.html` styled in **OSCP/OWASP penetration testing format**, including:
>    - Executive Summary
>    - Test Overview (OWASP OTG-CONFIG-004)
>    - Methodology
>    - Findings Table (File Path, Status, Risk Level, Evidence)
>    - Detailed Findings with request/response snippets
>    - Remediation Recommendations
>    - Conclusion
> 8. The HTML report must be **visually clean**, use a monospace font for code, color-coded risk indicators (Red/Amber/Green), and include a pentesting theme consistent with OSCP report aesthetics (e.g., dark headers, professional layout).
> 9. The script must be **non-destructive** — it should only perform read/access operations.
> 10. Include error handling for network issues, authentication failures, and missing paths.
> 11. Output verbose logging to console during execution and save raw responses in a `/logs` directory if needed.
> 12. Ensure the script can be run with a simple command: `python dvwa_backup_file_test.py`
> 13. The script should automatically detect and handle DVWA’s CSRF tokens during login.

> Ensure the script is modular, well-commented, and includes a `requirements.txt` suggestion (e.g., `requests`, `BeautifulSoup4`).

> At the end of execution, print:  
> `[+] Report generated: ./reports/DVWA_Backup_Files_Report.html`

---

## Expected Output

- `dvwa_backup_file_test.py` – The main Python testing script.
- `backup_files.txt` – Wordlist of backup filenames/extensions to test.
- `reports/DVWA_Backup_Files_Report.html` – Styled HTML report in OSCP format.

---

## Notes

- Assume DVWA is configured at `http://localhost/dvwa` and XAMPP is running Apache/MySQL.
- Security level in DVWA can be set to "Low" for testing purposes.
- The script should crawl the authenticated areas of DVWA to identify referenced files.
- The HTML report should be self-contained (inline CSS/JS) for portability.

---

## Usage Example

```bash
python dvwa_backup_file_test.py