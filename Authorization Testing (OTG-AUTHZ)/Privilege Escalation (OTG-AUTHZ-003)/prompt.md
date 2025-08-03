# AI Prompt: Privilege Escalation Testing Script for DVWA with OSCP-Style HTML Report

## Objective

Create a detailed prompt for an AI coding agent to generate a **Python automation script** that tests for **Privilege Escalation** vulnerabilities (OWASP **OTG-AUTHZ-003**) on **DVWA (Damn Vulnerable Web Application)** running locally via **XAMPP on `http://localhost/dvwa`**.

The script must:
- Test for privilege escalation vulnerabilities where a low-privileged user can gain higher privileges
- Simulate real-world attack scenarios
- Generate a professional, **OSCP/OWASP-style penetration test report** in a standalone, well-designed **HTML file** with embedded styling (no external resources)

---

## Prompt for AI Coding Agent

You are an advanced offensive security automation engineer. Your task is to write a **Python script** that performs an automated security assessment of **privilege escalation** vulnerabilities (OWASP Testing Guide v4 **OTG-AUTHZ-003**) in DVWA.

### 1. **Target Environment**
- Assume DVWA is running on `http://localhost/dvwa` via XAMPP
- Test with **Security Level: Low** (default DVWA configuration)
- Use default credentials:
  - Admin: `admin` / `password`
  - Regular user: `gordonb` / `abc123`

### 2. **Privilege Escalation Testing Scope**
Test the following **privilege escalation scenarios**:

#### **A. Session/Role Manipulation**
- Login as regular user (`gordonb`)
- Attempt to modify session cookies or parameters to gain admin privileges
- Test for insecure session handling
- Check if role/privilege information is stored client-side

#### **B. Direct Access to Admin Functionality**
- After logging in as regular user, attempt to access admin-only pages:
  - `/vulnerabilities/csrf/`
  - `/vulnerabilities/upload/`
  - `/vulnerabilities/captcha/`
  - `/security.php`
  - `/setup.php`

#### **C. Parameter Tampering**
- Test if privilege escalation is possible through:
  - `?admin=true` parameter
  - `?role=admin` parameter  
  - `?privilege=high` parameter
  - Hidden form fields manipulation

#### **D. Password Reset Abuse**
- Test if password reset functionality can be abused to escalate privileges
- Attempt to reset admin password as regular user

### 3. **Script Functionality Requirements**
- Use `requests` and `BeautifulSoup` for session handling and parsing
- Perform login as a **low-privilege user** (`gordonb`/`abc123`)
- Attempt to access **admin-only functionality**
- Capture HTTP status codes, response lengths, and content indicators
- Detect if administrative pages are accessible to regular users
- Log all attempts and outcomes
- Handle session isolation properly

### 4. **Report Generation**
Generate a **standalone HTML report** named: