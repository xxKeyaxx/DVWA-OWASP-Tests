# AI Prompt: Insecure Direct Object Reference (IDOR) Testing Script for DVWA with OSCP-Style HTML Report

## Objective

Create a detailed prompt for an AI coding agent to generate a **Python automation script** that tests for **Insecure Direct Object References (IDOR)** vulnerabilities (OWASP **OTG-AUTHZ-004**) on **DVWA (Damn Vulnerable Web Application)** running locally via **XAMPP on `http://localhost/dvwa`**.

The script must:
- Test for IDOR vulnerabilities where direct object references can be manipulated
- Focus on the specific IDOR vulnerability in DVWA's Authorization Bypass section
- Generate a professional, **OSCP/OWASP-style penetration test report** in a standalone, well-designed **HTML file** with embedded styling

---

## Prompt for AI Coding Agent

You are an advanced offensive security automation engineer. Your task is to write a **Python script** that performs an automated security assessment of **Insecure Direct Object Reference (IDOR)** vulnerabilities (OWASP Testing Guide v4 **OTG-AUTHZ-004**) in DVWA.

### 1. **Target Environment**
- Assume DVWA is running on `http://localhost/dvwa` via XAMPP
- Test with **Security Level: Low** (default DVWA configuration)
- Use default credentials:
  - Regular user: `gordonb` / `abc123`

### 2. **IDOR Testing Scope**
Test the **Authorization Bypass** vulnerability at `http://localhost/dvwa/vulnerabilities/authbypass/` which demonstrates IDOR through:
- Direct manipulation of the `userid` parameter
- Accessing user data without proper authorization checks
- Enumerating user IDs to discover all system users

### 3. **Script Functionality Requirements**
- Use `requests` and `BeautifulSoup` for session handling and parsing
- Login as a regular user (`gordonb`/`abc123`)
- Test the IDOR vulnerability by manipulating the `userid` parameter
- Test user ID values: 1, 2, 3, 4, 5, 999 (non-existent)
- For each test, capture:
  - HTTP status code
  - Response length
  - Presence of user data
  - Admin privilege indicators
- Detect if unauthorized user data can be accessed
- Log all attempts and outcomes

### 4. **IDOR-Specific Testing Logic**
The script must:
- Verify that user ID manipulation allows access to other users' data
- Check for admin privilege disclosure (userid=1)
- Test for user enumeration through response differences
- Determine if the application properly enforces access controls
- Identify the specific IDOR vulnerability pattern

### 5. **Report Generation**
Generate a **standalone HTML report** named: