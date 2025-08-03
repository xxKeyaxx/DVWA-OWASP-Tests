# AI Prompt: Bypassing Authorization Schema Testing Script for DVWA with OSCP-Style HTML Report

## Objective

Create a detailed prompt for an AI coding agent to generate a **Python automation script** that tests for **Bypassing Authorization Schema** vulnerabilities (OWASP **OTG-AUTHZ-002**) on **DVWA (Damn Vulnerable Web Application)** running locally via **XAMPP on `http://localhost/dvwa`**.

The script must:
- Actively test for privilege escalation and access control flaws
- Attempt to bypass role-based access controls
- Simulate low-privilege user access and attempt to reach admin-only pages
- Generate a professional, **OSCP/OWASP-style penetration test report** in a standalone, well-designed **HTML file** with embedded styling (no external resources)

---

## Prompt for AI Coding Agent

You are an advanced offensive security automation engineer. Your task is to write a **Python script** that performs an automated security assessment of **authorization mechanisms** in DVWA to detect **authorization bypass vulnerabilities** (OWASP Testing Guide v4 **OTG-AUTHZ-002**).

The script should:

### 1. **Target Environment**
- Assume DVWA is running on `http://localhost/dvwa` via XAMPP
- Test with **Security Level: Low** (default DVWA configuration)
- Use default credentials:
  - Admin: `admin` / `password`
  - Regular user: `user` / `password` *(if user exists; otherwise create or simulate)*

### 2. **Authorization Bypass Testing Scope**
Test the following **access control weaknesses**:
- Attempt to access **admin-only pages** (e.g., `security.php`, `setup.php`) as a low-privileged user
- Direct URL access to restricted areas without proper session/role
- Parameter manipulation (e.g., `?page=admin`, `user_id=admin`)
- HTTP method tampering (e.g., using `GET` instead of `POST` for restricted actions)
- Session reuse or privilege escalation via cookie/session manipulation
- Hidden pages discovery (e.g., `/vulnerabilities/csrf/`, `/phpinfo.php`)

### 3. **Script Functionality Requirements**
- Use `requests` and `BeautifulSoup` for session handling and parsing
- Perform login as a **low-privilege user** (simulate user if needed)
- Attempt to access **restricted pages** without authorization
- Capture HTTP status codes, response lengths, and content indicators
- Detect if sensitive pages are accessible (e.g., presence of "Admin", "Setup", "Configuration")
- Log all attempts and outcomes

### 4. **Report Generation**
Generate a **standalone HTML report** named: