# AI Coding Agent Prompt: Webpage Comments & Metadata Review Script for DVWA (OTG-INFO-005)

## Objective

Create a Python script that automatically reviews **webpage comments and metadata** for information leakage as defined in the **OWASP Testing Guide (OTG-INFO-005)**. The target is **DVWA (Damn Vulnerable Web App)** running on **localhost via XAMPP**. The script must crawl accessible pages, extract HTML comments, metadata (e.g., `<meta>` tags, version info, hidden fields), and analyze them for sensitive data. It should then generate a professional, well-structured **HTML report in OSCP/OWASP-style formatting**, visually consistent with penetration testing standards.

---

## Prompt for AI Coding Agent

You are an expert AI assistant specializing in security automation and offensive security tool development. Your task is to write a **Python script** that performs the following:

---

### 1. **Target Environment**

- **Application**: DVWA (Damn Vulnerable Web App)
- **Host**: `http://localhost`
- **Port**: `80` (default XAMPP)
- **Path**: `/dvwa/`
- **Assumption**: DVWA is fully set up, accessible at `http://localhost/dvwa/`, and the user can navigate to key pages (e.g., login, home, modules) — **no authentication required** for initial page access (login page is public).
- **Scope**: Publicly accessible HTML pages (e.g., login page, index, module pages if reachable).

---

### 2. **Functionality Requirements**

#### A. **Page Discovery & Crawling**
- Start from `http://localhost/dvwa/` and fetch the **login page**.
- Extract all `<a>` links and known DVWA module paths:
  - `/index.php`
  - `/login.php`
  - `/setup.php`
  - Modules: `/vulnerabilities/xss_r/`, `/vulnerabilities/sqli/`, etc.
- Use `requests` and `BeautifulSoup` to parse HTML and extract:
  - HTML comments (`<!-- ... -->`)
  - `<meta>` tags (name, content)
  - Hidden form inputs (`<input type="hidden">`)
  - Version indicators in text (e.g., "DVWA v1.10")
  - Developer notes, TODOs, debug messages

#### B. **Information Leakage Detection**
- Search for:
  - Hardcoded credentials (e.g., `<!-- admin:pass -->`)
  - Debug comments (e.g., `<!-- TODO: fix SQLi -->`, `<!-- DEV: test mode enabled -->`)
  - Version numbers or build info
  - Internal paths (e.g., `<!-- Backup at /var/www/dvwa_backup -->`)
  - Hidden parameters (e.g., `<input type="hidden" name="debug" value="1">`)
  - Deprecated or test endpoints mentioned in comments
- Classify findings by **severity**:
  - **Critical**: Hardcoded credentials
  - **High**: Debug mode enabled, internal paths
  - **Medium**: Version disclosure, TODOs with hints
  - **Low**: Generic comments, unused links

#### C. **Authentication Handling (Optional but Preferred)**
- If possible, log in using default credentials (`admin:password`) to access protected pages.
- Use the session to extract comments from authenticated pages.
- Handle CSRF tokens from `login.php` (DVWA requires `user_token`).

#### D. **Reporting**
- Generate a standalone **HTML report** named:  
  `OTG-INFO-005_Webpage_Comments_Metadata_Report.html`
- Style the report in **OSCP/OWASP pentest report format**:
  - Dark theme with green/white/blue accents
  - Embedded CSS (no external files)
  - Google Fonts: `Roboto`, `Source Code Pro` via CDN
  - Printer-friendly and responsive
- Report Sections:
  1. **Title Page**: Report Title, Target, Date, Author ("AI Security Agent")
  2. **Executive Summary**: Overview of findings and risk
  3. **Test Details**: OWASP Test ID: OTG-INFO-005
  4. **Methodology**: Tools, scope, crawling approach
  5. **Findings Summary**: Grid of severity counts (Critical/High/Medium/Low)
  6. **Findings Table**: File/Page, Comment Snippet, Severity, Description
  7. **Detailed Findings**: Expandable entries with full context and code snippets
  8. **Remediation Recommendations**: Per finding type
  9. **Conclusion**
- Use **severity badges** (red/orange/yellow/green) and syntax-highlighted code blocks.

---

### 3. **Technical Specifications**

- Language: **Python 3**
- Required Libraries:
  - `requests` (HTTP requests, session handling)
  - `BeautifulSoup4` (HTML parsing)
  - `re` (regex for comment extraction)
  - `os`, `datetime` (file and timestamp)
- **No user input required** — script runs autonomously.
- Base URL: `http://localhost/dvwa/`
- Handle:
  - Connection errors (e.g., DVWA not running)
  - Authentication flow (extract `user_token`, submit login)
- Output:
  - Print summary to console
  - Save full HTML report to disk

---

### 4. **Security & Ethics**
- Script is for **authorized testing only**.
- Include disclaimer in HTML footer:
  > *This report was generated for educational purposes in a controlled environment (DVWA). Unauthorized testing on systems without permission is illegal.*

---

### 5. **Deliverables**

The AI must generate:
1. A complete **Python script** (`comments_metadata_scanner.py`)
2. The script must **self-generate** the HTML report upon execution
3. The HTML report must be **visually aligned with OSCP-style penetration test reports**, matching the design quality of the OTG-INFO-003 report previously generated.

---

### Example Finding Entry (HTML)
```html
<div class="finding high">
  <h3>Debug Mode Enabled in Comment</h3>
  <p><strong>Page:</strong> http://localhost/dvwa/login.php</p>
  <p><strong>Severity:</strong> <span class="badge high">High</span></p>
  <p><strong>Comment:</strong> <!-- DEV: debug=1 enabled for testing --> </p>
  <p><strong>Description:</strong> Debug mode is enabled in comments, indicating potential test configuration exposed.</p>
  <p><strong>Remediation:</strong> Remove debug comments and disable test features in production.</p>
</div>