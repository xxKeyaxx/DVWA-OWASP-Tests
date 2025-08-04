# AI Coding Agent Prompt: Test Default Credentials (OTG-AUTHN-002)

## Objective

Create a detailed prompt for an AI coding agent to generate a **Python-based security testing script** that automates the detection of **Default Credentials (OTG-AUTHN-002)** on **DVWA (Damn Vulnerable Web App)** running locally via **XAMPP on `http://localhost/dvwa`**. The script must attempt login using a curated list of common default credentials and generate a professional, **OWASP/OSCP-style HTML report** upon completion.

The output should be a standalone, well-documented `.py` script that is safe, non-invasive (within ethical testing scope), and suitable for educational and penetration testing lab environments.

---

## Prompt for AI Coding Agent

> You are a cybersecurity automation expert tasked with creating a vulnerability assessment tool for the **OWASP Testing Guide v4.2** test case **OTG-AUTHN-002: Testing for Default Credentials**.

### 🎯 Target Application
- **DVWA (Damn Vulnerable Web Application)** running on a local XAMPP server.
- Base URL: `http://localhost/dvwa`
- Login Page: `http://localhost/dvwa/login.php`
- Form Method: `POST`
- Form Fields: `username`, `password`, `Login` (submit), and `user_token` (CSRF token, if security level > Low)

---

### ✅ Functional Requirements

#### 1. **Default Credentials Dictionary**
Implement a small, targeted list of **common default credential pairs**, including:
```python
default_creds = [
    ("admin", "password"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("guest", "guest"),
    ("user", "user"),
    ("test", "test"),
    ("admin", ""),
    ("", ""),
    ("dvwa", "dvwa")
]