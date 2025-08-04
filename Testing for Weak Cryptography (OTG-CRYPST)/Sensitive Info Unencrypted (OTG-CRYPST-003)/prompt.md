# AI Agent Prompt: OTG-CRYPST-003 Testing Script & Report for DVWA

## Objective

Create a **Python-based security testing script** that automatically detects whether sensitive information (e.g., login credentials, session tokens) is transmitted over **unencrypted HTTP** in a **DVWA instance running on `http://localhost` via XAMPP**.

Then, generate a **well-designed, OSCP/OWASP-style HTML report** summarizing the findings, methodology, and risk level — suitable for inclusion in penetration testing reports.

---

## 🛠️ Task Breakdown

### Part 1: Python Script Requirements

Write a **Python script (`otg_cryst_003_tester.py`)** that:

1. **Connects to DVWA** at `http://localhost/dvwa/` and checks:
   - Whether the site is served over **HTTP (not HTTPS)**.
   - If the login form submits credentials via `POST` over HTTP.
   - Whether the `Set-Cookie` header includes `PHPSESSID` **without the `Secure` flag**.
   - Whether credentials appear in plaintext in responses or requests.

2. **Simulates a login attempt** (use credentials: `admin` / `password`) using the `requests` library, while:
   - Capturing request/response headers and bodies.
   - Ensuring DVWA security is set to "Low" (if needed, guide user to set it manually).

3. **Analyzes traffic for insecure transmission**, including:
   - Plaintext password in POST body.
   - Session cookie sent without `Secure` or `HttpOnly` flags.
   - Any redirects over HTTP.

4. **Outputs structured findings** (as a dictionary or JSON) containing:
   - Target URL
   - Protocol used (HTTP/HTTPS)
   - Sensitive data exposed
   - Cookie security flags
   - Risk level (High)
   - Evidence (request/response snippets)

> ⚠️ Do **not** perform MiTM or packet capture (e.g., with Scapy) — rely on HTTP observability via `requests` and manual inspection guidance.

---

### Part 2: HTML Report Requirements

Generate an **HTML report** named `OTG-CRYPST-003_Report_DVWA.html` that mimics the **style of OSCP or OWASP reports**, including:

#### ✅ Structure:
- **Title Section**: `OTG-CRYPST-003: Sensitive Information Sent via Unencrypted Channels`
- **Test Date & Target**: Auto-injected current date and `http://localhost/dvwa/`
- **Risk Level**: `High` (with red color indicator)
- **Vulnerability Summary**: Brief description of the issue
- **Impact**: Unauthorized access via network sniffing
- **Mitigation**: Enforce HTTPS, use Secure/HttpOnly flags, HSTS
- **Steps to Reproduce**:
  - Access DVWA login
  - Intercept login request
  - Observe plaintext credentials
- **Proof of Concept**:
  - Code block showing intercepted POST data
  - HTTP response headers showing `Set-Cookie: PHPSESSID=...` without `Secure`
- **Tools Used**: `Python`, `requests`, `Burp Suite (optional)`
- **References**:
  - [OWASP OTG-CRYPST-003](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels)
  - OSCP Guidelines

#### ✅ Design:
- Clean, **monospace font** (e.g., `Courier New`, `Consolas`)
- Dark red/black theme (like OSCP exam reports)
- Use `<pre>`, `<code>`, and styled `<div>`s for sections
- Responsive layout with header, sections, and footer
- Include a simple **"Vulnerability Confirmed"** banner in red

---

## 📁 Output Files

The script should generate:
1. `otg_cryst_003_tester.py` – the main testing script
2. `OTG-CRYPST-003_Report_DVWA.html` – the styled HTML report
3. (Optional) `traffic_capture.json` – raw request/response logs

---

## 🧪 Assumptions

- DVWA is running at `http://localhost/dvwa/`
- DVWA is configured with default credentials:
  - Username: `admin`
  - Password: `password`
- Security level is set to **"Low"**
- Web server: **XAMPP (Apache)** on localhost
- No HTTPS is configured (default XAMPP setup)

---

## 📝 Notes for the AI Agent

- Write **clean, commented, and educational code** — this may be used for learning.
- The HTML report should be **standalone** (no external CSS/JS).
- Use **inline CSS** for styling to ensure portability.
- Emphasize **real-world impact** and **professional reporting tone**.
- If automatic detection is limited, include **manual verification steps** in the report.

---

## 🎯 Final Goal

Produce a **complete, ready-to-run solution** that:
- Demonstrates **OTG-CRYPST-003** on DVWA
- Educates users on insecure transmission risks
- Generates a **professional-looking report** in the style of OSCP penetration test outputs

> ✅ This will be used for training, CTF prep, and security demonstrations.

---