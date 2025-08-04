# AI Coding Agent Prompt: Local Storage (OTG-CLIENT-012) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that **assesses the security implications of browser Local Storage usage** in **Damn Vulnerable Web Application (DVWA)** running via **XAMPP on localhost**. While DVWA does not natively use `localStorage` or `sessionStorage`, the script must:

1. **Check for actual Local Storage usage** by the application
2. **Demonstrate how stored XSS vulnerabilities could be used to manipulate Local Storage**
3. **Analyze the risk** of client-side data storage in the context of existing vulnerabilities
4. Generate a professional, well-structured **OWASP/OSCP-style HTML report** that educates on Local Storage risks, even if not directly exploited in DVWA

> **Note**: This test is **educational and conceptual** — it demonstrates what *would* happen if DVWA stored sensitive data in `localStorage`, and how XSS can fully compromise it.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Set to **Low** (automatically configure via script)
- Test relevant modules:
  - `/vulnerabilities/xss_s/` (Stored XSS — to demonstrate localStorage manipulation)
  - `/` (main page — to check localStorage state)

### 2. **Testing Objective: OTG-CLIENT-012 – Testing for Local Storage**
- Determine if DVWA uses `localStorage` or `sessionStorage` for client-side data storage
- Use **Selenium** to:
  - Read current `localStorage` and `sessionStorage` contents
  - Detect any existing keys/values
- Exploit **Stored XSS** vulnerability to:
  - Inject JavaScript that writes to `localStorage` (e.g., `localStorage.setItem('dvwa_attacker', 'true')`)
  - Simulate storage of sensitive data
- Verify that injected scripts can **read, write, and persist** data in Local Storage
- Document that **if DVWA stored session tokens or PII in localStorage, they would be fully accessible via XSS**

### 3. **Automation Requirements**
- Use `selenium` for browser automation and DOM/Storage interaction
- Use `requests` and `BeautifulSoup` for login and CSRF token handling
- Automate login to DVWA
- Set security level to **Low**
- Navigate to **Stored XSS** page and inject a payload that manipulates `localStorage`
- Use `driver.execute_script()` to:
  - Check initial `localStorage` state
  - Verify payload execution
  - Read back injected data
- Handle all exceptions (e.g., element not found, timeout)
- Close browser after testing

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-012_Report.html` file with the following structure and styling:

#### Report Structure
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>OSCP-Style Security Assessment Report</title>
  <style>
    /* OSCP-inspired styling: monospace, dark theme, clean layout */
    body { 
      font-family: 'Courier New', monospace; 
      background: #111; 
      color: #00FF00; 
      padding: 20px; 
      line-height: 1.6;
    }
    .header { text-align: center; margin-bottom: 30px; }
    h1, h2, h3 { color: #00CCFF; border-bottom: 1px solid #00CCFF; padding-bottom: 5px; }
    .section { margin: 20px 0; }
    pre { 
      background: #222; 
      padding: 12px; 
      border-left: 5px solid #00CCFF; 
      overflow-x: auto; 
      font-size: 0.9em;
      color: #FFCC00;
    }
    .evidence { color: #FFCC00; font-weight: bold; }
    .recommendation { color: #AAFF00; }
    .vulnerable { color: #FF5555; font-weight: bold; }
    .safe { color: #55FF55; }
    .info { color: #55AAFF; }
    footer { margin-top: 60px; font-size: 0.8em; text-align: center; color: #666; }
    code { background: #333; padding: 2px 4px; border-radius: 3px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Test ID:</strong> OTG-CLIENT-012</p>
    <p><strong>Vulnerability:</strong> Local Storage Security</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Assess the security of client-side storage mechanisms (localStorage, sessionStorage) and their exposure to XSS.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-012</p>
    <p><strong>Note:</strong> DVWA does not natively use Local Storage. This test demonstrates the <strong>theoretical risk</strong> and how XSS can fully compromise localStorage if used.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Check initial <code>localStorage</code> and <code>sessionStorage</code> state.</p>
    <p>4. Exploit Stored XSS to inject JavaScript that manipulates <code>localStorage</code>.</p>
    <p>5. Verify that data can be written, read, and persisted.</p>
    <p>6. Analyze security implications.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Local Storage Usage</h3>
    <p><strong>Status:</strong> <span class="info">Not In Use (But Exploitable)</span></p>
    <pre>Initial localStorage: {}
Injected Payload: <script>localStorage.setItem('xss_test', 'success');</script>
Final localStorage: {"xss_test": "success"}</pre>
    <p class="evidence"><strong>Evidence:</strong> Stored XSS vulnerability allows full read/write access to localStorage. If DVWA stored session tokens here, they would be compromised.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>If DVWA stored sensitive data (e.g., tokens, user IDs) in localStorage, an XSS vulnerability would lead to full account compromise. Unlike HttpOnly cookies, localStorage is fully accessible to JavaScript and cannot be protected from XSS.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Never store session tokens or PII in localStorage or sessionStorage.</p>
    <p class="recommendation">- Use HttpOnly cookies for session management.</p>
    <p class="recommendation">- Implement strong Content Security Policy (CSP) to mitigate XSS.</p>
    <p class="recommendation">- Sanitize all user inputs to prevent XSS, which is the primary vector for localStorage abuse.</p>
    <p class="recommendation">- Educate developers on secure client-side data storage practices.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>