# AI Coding Agent Prompt: Test Browser Cache Weakness (OTG-AUTHN-006)

## Objective

Create a detailed and comprehensive prompt for an AI coding agent to generate a **Python-based security testing script** that evaluates **Browser Cache Weakness** in **DVWA (Damn Vulnerable Web Application)** running on a **localhost XAMPP environment** (`http://localhost/dvwa`). The test must align with **OWASP Testing Guide v4.2** test case **OTG-AUTHN-006: Testing for Browser Cache Weakness**.

The script should:
- Analyze HTTP response headers for proper cache control directives.
- Detect if sensitive authenticated content is served without cache protection.
- Identify missing or weak `Cache-Control`, `Pragma`, and `Expires` headers.
- Generate a professional, **OWASP/OSCP-style HTML report** with findings, risk assessment, and remediation guidance.

The final output must be a standalone, well-documented `.py` script suitable for **educational, lab-based penetration testing** environments.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation engineer specializing in web security and secure headers testing. Your task is to develop a Python script that performs an automated assessment of **OTG-AUTHN-006: Browser Cache Weakness** on **DVWA** hosted locally via **XAMPP**.

---

### 🎯 Target Environment

- **Application**: DVWA (Damn Vulnerable Web Application)
- **Base URL**: `http://localhost/dvwa`
- **Login Page**: `http://localhost/dvwa/login.php`
- **Protected Pages**:
  - `http://localhost/dvwa/index.php`
  - `http://localhost/dvwa/vulnerabilities/sqli/`
  - `http://localhost/dvwa/security.php`
  - `http://localhost/dvwa/phpinfo.php`
- **Authentication Mechanism**: Session-based (PHPSESSID cookie)

> Note: The script should test both **unauthenticated** and **authenticated** pages for cache-related header weaknesses.

---

### ✅ Functional Requirements

#### 1. **Authentication Flow Handling**
- Use `requests.Session()` to simulate authenticated and unauthenticated sessions.
- Parse login page with `BeautifulSoup` to extract CSRF tokens (`user_token`) when needed.
- Perform a successful login to access protected content.

#### 2. **Cache Weakness Testing Techniques**
Implement the following checks:

##### a) **HTTP Header Analysis**
For each page tested, analyze the following response headers:
- `Cache-Control`
- `Pragma`
- `Expires`
- `ETag`
- `Last-Modified`

Check for:
- Missing or insecure `Cache-Control` directives (e.g., absence of `no-store`, `no-cache`)
- Presence of `public` or `max-age` on sensitive pages
- Missing `Pragma: no-cache` (for HTTP/1.0 compatibility)
- Missing `Expires: 0` or a past date

##### b) **Sensitive Page Testing**
Test the following page types:
- Login page (`login.php`)
- Authenticated dashboard (`index.php`)
- Vulnerability pages (e.g., SQLi, XSS)
- Configuration pages (e.g., `security.php`)

##### c) **Cache Vulnerability Detection**
Define a page as **vulnerable** if:
- It contains sensitive data (e.g., user info, forms, vulnerabilities).
- It lacks proper cache prevention headers.
- It allows caching of authenticated content.

##### d) **Public vs Private Content Classification**
- Classify pages that should **never be cached** (e.g., authenticated content).
- Flag any page missing `Cache-Control: no-store, no-cache, must-revalidate` or equivalent.

> All tests must be **non-destructive** and safe for lab use.

#### 3. **Security Assessment Logic**
- Define vulnerabilities if:
  - Sensitive pages are served without cache protection.
  - `Cache-Control` allows storage (`public`, `max-age>0`).
  - No `Pragma` or `Expires` headers for backward compatibility.
  - Authenticated content can be cached by browser or intermediaries.

---

### 📄 Report Generation Requirements

After testing, generate a **standalone HTML report** named:  
`OTG-AUTHN-006_Report.html`

The report must follow **OSCP-style formatting** and include:

#### 📑 Report Sections
- **Title**: `OTG-AUTHN-006: Testing for Browser Cache Weakness`
- **Test Date & Time**
- **Target URL**
- **Test Result**: `Failed` (weak/no cache controls) or `Passed` (strong cache protection)
- **Vulnerability Description**: Explain how improper caching can expose sensitive data via browser history, shared machines, or proxy caches.
- **Impact**: Medium — risk of information disclosure on shared systems.
- **Findings**:
  - Table of tested pages and their cache headers.
  - Highlight pages missing secure directives.
  - List insecure cache policies.
- **Proof of Concept (PoC)**:
  - Example response headers showing missing cache controls.
  - cURL command to reproduce:  
    `curl -v http://localhost/dvwa/index.php --cookie "PHPSESSID=..." | grep -i cache`
- **Remediation**:
  - Set `Cache-Control: no-store, no-cache, must-revalidate, private`
  - Add `Pragma: no-cache`
  - Set `Expires: 0`
  - Apply to all authenticated and sensitive pages.
- **References**:
  - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
  - [OTG-AUTHN-006 - OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authentication_Testing/06-Testing_for_Browser_Cache_Weakness)
  - [RFC 9111 - HTTP Caching](https://httpwg.org/specs/rfc9111.html)

---

### 🎨 Report Design (OSCP Style)

- **Font**: Monospace (`Courier New`, `Consolas`)
- **Color Scheme**:
  - Header: Dark blue (`#003366`) with white text
  - Status: Red (`#cc0000`) for "Failed", Green (`#008800`) for "Passed"
- **Layout**:
  - Clean, centered container
  - Section headers with bottom borders
  - Pre-formatted blocks for headers and PoC
  - Table for page-by-page analysis
- **Styling**: Use **inline CSS only** (no external files)
- **Print-Friendly**: Ensure readability in PDF/print format

---

### 🖨️ Output & Console Logging

- Print real-time progress: