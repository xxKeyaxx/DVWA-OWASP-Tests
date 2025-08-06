# AI Coding Agent Prompt: Webserver Metafile Review Script for DVWA (OTG-INFO-003)

## Objective

Create a Python script that automatically reviews webserver metafiles for information leakage as defined in the OWASP Testing Guide (OTG-INFO-003). The target is **DVWA (Damn Vulnerable Web App)** running on **localhost via XAMPP**. The script must scan for common metafiles and configuration files that may expose sensitive information, and generate a professional, well-structured HTML report in **OSCP/OWASP-style formatting**.

---

## Prompt for AI Coding Agent

You are an expert AI assistant specializing in security automation and penetration testing tool development. Your task is to write a **Python script** that performs the following:

### 1. **Target Environment**
- **Application**: DVWA (Damn Vulnerable Web App)
- **Host**: `http://localhost`
- **Port**: `80` (default XAMPP)
- **Path**: `/dvwa/` (typical installation path)
- **Assumption**: DVWA is fully set up and accessible via `http://localhost/dvwa/`

---

### 2. **Functionality Requirements**

#### A. **Metafile Scanning**
- Scan for common metafiles and backup/configuration files that may leak sensitive information.
- Use a predefined list of high-risk files, including but not limited to:
  - `.git/HEAD`, `.git/config`
  - `.htaccess`, `.htpasswd`
  - `robots.txt`
  - `backup.sql`, `backup.zip`, `backup.tar.gz`
  - `config.php~`, `config.php.bak`, `config.old`
  - `phpinfo.php`, `test.php`
  - `.env`, `.DS_Store`, `Thumbs.db`
  - `README.md`, `CHANGELOG.txt`, `license.txt`
  - `web.config` (for cross-platform relevance)
- Perform **HTTP GET requests** to each endpoint derived from the base URL + filename.
- Record:
  - HTTP status code
  - Response length
  - Whether the file is accessible
  - Any exposed sensitive data (e.g., paths, DB credentials, usernames)

#### B. **Intelligent Detection**
- If `.git/HEAD` is found, flag it as **Critical** and attempt to extract repository info.
- If `config.php` or similar is accessible or has backups, parse response for:
  - Database credentials (`$db_user`, `$db_password`)
  - Absolute file paths
  - DVWA security level
- Detect presence of `phpinfo.php` — if found, flag as **High** risk.

#### C. **Reporting**
- Generate a **standalone HTML report** named: `OTG-INFO-003_Webserver_Metafile_Review_Report.html`
- Style the report in **OSCP/OWASP pentest report format**:
  - Dark theme with green/white/blue accents
  - Professional layout with sections:
    - **Title Page**: Report Title, Target, Date, Author ("AI Security Agent")
    - **Executive Summary**: Brief overview of findings
    - **Test Details**: OWASP Test ID: OTG-INFO-003
    - **Methodology**: Tools used (script), scope, approach
    - **Findings Table**: Columns: Filename, Path, Status, Severity (Critical/High/Medium/Low), Description
    - **Detailed Findings**: Expandable entries with raw response snippets (if sensitive data found)
    - **Remediation Recommendations**: For each finding
    - **Conclusion**
- Use embedded **CSS** for styling (no external files). Use Google Fonts (e.g., `Roboto`, `Courier New`) via CDN.
- Include a **severity badge system** (e.g., red for Critical, orange for High).
- Make the report **printer-friendly** and responsive.

---

### 3. **Technical Specifications**

- Language: **Python 3**
- Required Libraries:
  - `requests` (for HTTP requests)
  - `os`, `datetime`, `json` (standard)
- Do **not** require user input during execution.
- Base URL: `http://localhost/dvwa/`
- Handle connection errors gracefully (e.g., DVWA not running).
- Output:
  - Print summary to console
  - Save full report as HTML in current directory

---

### 4. **Security & Ethics**
- Script is for **educational and authorized testing only**.
- Include a disclaimer in the HTML report footer:
  > *This report was generated for educational purposes in a controlled environment (DVWA). Unauthorized testing on systems without permission is illegal.*

---

### 5. **Deliverables**

The AI must generate:
1. A complete **Python script** (`metafile_scanner.py`)
2. The script must **self-generate** the HTML report upon execution
3. The HTML report must be **visually aligned with OSCP-style penetration test reports**

---

### Example Finding Entry (HTML)
```html
<div class="finding critical">
  <h3>.git/HEAD Accessible</h3>
  <p><strong>Path:</strong> http://localhost/dvwa/.git/HEAD</p>
  <p><strong>Severity:</strong> <span class="badge critical">Critical</span></p>
  <p><strong>Description:</strong> Git metadata is exposed, allowing attackers to reconstruct source code and potentially uncover secrets.</p>
  <p><strong>Remediation:</strong> Remove .git directory from production or block access via web server configuration.</p>
</div>