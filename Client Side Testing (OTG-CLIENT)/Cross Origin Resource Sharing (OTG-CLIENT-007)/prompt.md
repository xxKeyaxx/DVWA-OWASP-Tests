# AI Coding Agent Prompt: Cross-Origin Resource Sharing (OTG-CLIENT-007) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that **analyzes** `http://localhost/dvwa/` for **Cross-Origin Resource Sharing (CORS)** configurations as part of testing **OTG-CLIENT-007**. Since DVWA does not implement modern API-based interactions or dynamic client-side resource sharing, the script should focus on **detecting the presence (or absence) of CORS-related HTTP headers** and **assessing whether the application's design prevents or allows cross-origin data access**.

The script must generate a professional, well-structured **OWASP/OSCP-style HTML report** that clearly explains:
- What CORS is
- Why DVWA is not suitable for full OTG-CLIENT-007 exploitation
- Whether any CORS-related headers are present
- The security implications
- Recommendations for secure CORS implementation

> **Note**: This script is **not expected to demonstrate active CORS exploitation** (e.g., stealing data via malicious frontend), as DVWA's architecture does not support it. Instead, it should serve as an **educational diagnostic tool**.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Not applicable (CORS testing is independent of DVWA security levels)
- Test relevant endpoints:
  - `/`
  - `/login.php`
  - `/security.php`
  - `/vulnerabilities/xss_r/`
  - `/vulnerabilities/xss_s/`
  - `/vulnerabilities/sqli/`
  - `/vulnerabilities/csrf/`

### 2. **Testing Objective: OTG-CLIENT-007 – Cross-Origin Resource Sharing**
- **Goal**: Determine if DVWA exposes any CORS-related headers or behaviors that could lead to cross-origin data leakage
- **Check for HTTP response headers**:
  - `Access-Control-Allow-Origin`
  - `Access-Control-Allow-Credentials`
  - `Access-Control-Allow-Methods`
  - `Access-Control-Allow-Headers`
  - `Access-Control-Expose-Headers`
  - `Access-Control-Max-Age`
- **Test both `GET` and `OPTIONS`** methods (preflight)
- **Analyze results**:
  - Is `Access-Control-Allow-Origin: *` present?
  - Is `Access-Control-Allow-Credentials: true` used with wildcard origin? (critical vulnerability)
  - Are origins being reflected unsafely?
- **Document that DVWA does not use AJAX/APIs**, so **no actual CORS-based attacks are possible**, but the header configuration should still be reviewed.

### 3. **Automation Requirements**
- Use `requests` to send `GET` and `OPTIONS` requests to DVWA endpoints
- Handle session login to ensure authenticated context
- Extract and log all CORS-related headers
- Attempt to detect **origin reflection** by sending custom `Origin` headers
- Example:
  ```python
  headers = {'Origin': 'https://evil.com'}
  response = session.get(url, headers=headers)
  if 'https://evil.com' in response.headers.get('Access-Control-Allow-Origin', ''):
      # Potential origin reflection vulnerability