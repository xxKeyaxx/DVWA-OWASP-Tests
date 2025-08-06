# AI Coding Agent Prompt: DVWA Enumerate Admin Interfaces (OTG-CONFIG-005)

## Objective

Create a Python script that automates the discovery and analysis of **administrative interfaces** on a locally running **Damn Vulnerable Web Application (DVWA)** instance via **XAMPP on localhost**. The script must identify common admin paths, configuration interfaces, and infrastructure management endpoints, and generate a professional **OWASP/OSCP-style penetration testing report** in a standalone, well-designed HTML file.

---

## Prompt for AI Coding Agent

> You are a skilled cybersecurity automation engineer tasked with creating a comprehensive security testing tool for DVWA (Damn Vulnerable Web Application) running on a local XAMPP server (`http://localhost/dvwa`). Your goal is to assess the exposure of administrative interfaces in accordance with **OWASP Testing Guide v4 - OTG-CONFIG-005: Enumerate Infrastructure and Application Admin Interfaces**.

> Develop a **Python script** that:
>
> 1. **Connects to DVWA** at `http://localhost/dvwa` and logs in using default credentials (`admin:password`) via session-based authentication (handle CSRF tokens if present).
> 2. **Scans for common administrative interface paths** such as:
>    - `/admin/`, `/administrator/`, `/admincp/`, `/cpanel/`, `/controlpanel/`
>    - `/wp-admin/`, `/phpmyadmin/`, `/mysql/`, `/db/`, `/database/`
>    - `/config/`, `/setup/`, `/install/`, `/install.php`
>    - `/server-status`, `/server-info`, `/phpinfo.php`
>    - `/backup/`, `/logs/`, `/debug/`, `/test/`
> 3. **Identifies infrastructure management interfaces** including:
>    - XAMPP control panel paths
>    - phpMyAdmin access
>    - Apache server-status and server-info
>    - MySQL/MariaDB admin interfaces
>    - PHP configuration interfaces
> 4. For each discovered interface, records:
>    - HTTP status code
>    - Redirect behavior
>    - Authentication requirements
>    - Content type and size
>    - Indicators of sensitive functionality
> 5. Uses a **comprehensive wordlist** of common admin paths and infrastructure interfaces.
> 6. **Generates a detailed HTML report** titled `DVWA_Admin_Interfaces_Report.html` styled in **OSCP/OWASP penetration testing format**, including:
>    - Executive Summary
>    - Test Overview (OWASP OTG-CONFIG-005)
>    - Methodology
>    - Findings Table (Path, Status, Type, Risk Level)
>    - Detailed Findings with screenshots (if possible) or response snippets
>    - Remediation Recommendations
>    - Conclusion
> 7. The HTML report must be **visually clean**, use a monospace font for code, color-coded risk indicators (Red/Amber/Green), and include a pentesting theme consistent with OSCP report aesthetics (e.g., dark headers, professional layout).
> 8. The script must be **non-destructive** — it should only perform read/access operations.
> 9. Include error handling for network issues, authentication failures, and missing paths.
> 10. Output verbose logging to console during execution.
> 11. Ensure the script can be run with a simple command: `python dvwa_admin_interface_test.py`
> 12. The script should automatically detect and handle DVWA’s CSRF tokens during login.
> 13. Include a section in the report that differentiates between:
>     - Application-level admin interfaces
>     - Database administration interfaces
>     - Server infrastructure interfaces
>     - Development/debug interfaces

> Ensure the script is modular, well-commented, and includes a `requirements.txt` suggestion (e.g., `requests`, `BeautifulSoup4`).

> At the end of execution, print:  
> `[+] Report generated: ./reports/DVWA_Admin_Interfaces_Report.html`

---

## Expected Output

- `dvwa_admin_interface_test.py` – The main Python testing script.
- `admin_paths.txt` – Wordlist of admin paths to test.
- `reports/DVWA_Admin_Interfaces_Report.html` – Styled HTML report in OSCP format.

---

## Notes

- Assume DVWA is configured at `http://localhost/dvwa` and XAMPP is running Apache/MySQL.
- The script should test both relative to DVWA root and at the server root.
- Security level in DVWA can be set to "Low" for testing purposes.
- The HTML report should be self-contained (inline CSS/JS) for portability.
- Focus on identifying interfaces that could provide elevated access or sensitive information.

---

## Usage Example

```bash
python dvwa_admin_interface_test.py