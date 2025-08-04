# AI Coding Agent Prompt: Client-Side URL Redirect (OTG-CLIENT-004) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that automates testing for **Client-Side URL Redirect (OTG-CLIENT-004)** on a local instance of **Damn Vulnerable Web Application (DVWA)** running via **XAMPP on localhost**. The script must detect and demonstrate client-side open redirect vulnerabilities and generate a professional, well-structured **OWASP/OSCP-style HTML report** styled to resemble official penetration testing reports.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Set to **Low** (automatically configure via script if possible)
- Test relevant modules: Any pages that perform client-side redirects (e.g., custom redirect scripts, links with `redirect=` parameters)

### 2. **Testing Objective: OTG-CLIENT-004 – Client-Side URL Redirect**
- Identify client-side redirect mechanisms that use user-controllable input (e.g., URL parameters like `?redirect=`, `?url=`, `?next=`)
- Test for **Open Redirect** vulnerabilities where an attacker can redirect users to arbitrary domains
- Use a **safe external test domain** such as `https://example.com` (non-malicious, publicly available for testing)
- Confirm redirect functionality by:
  - Analyzing JavaScript for `window.location`, `document.location`, or `window.open()` usage
  - Monitoring HTTP responses and browser navigation
  - Capturing redirect chains and final destinations

### 3. **Automation Requirements**
- Use `selenium` for browser automation to simulate real user interactions
- Use `requests` and `BeautifulSoup` for preliminary reconnaissance and session handling
- Automate login to DVWA
- Set security level to **Low**
- Search for redirect functionality in:
  - HTML source (links, meta refresh)
  - JavaScript files and inline scripts
  - URL parameters that suggest redirection
- Test redirect payloads such as:
  - `javascript:alert('Redirect')` (for detection)
  - `https://example.com` (safe external domain)
  - `//evil.com` (protocol-relative redirect)
- Validate if the application reflects or executes the redirect parameter without proper validation

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-004_Report.html` file with the following structure and styling:

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
    footer { margin-top: 60px; font-size: 0.8em; text-align: center; color: #666; }
    code { background: #333; padding: 2px 4px; border-radius: 3px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Test ID:</strong> OTG-CLIENT-004</p>
    <p><strong>Vulnerability:</strong> Client-Side URL Redirect</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify client-side URL redirect vulnerabilities that allow arbitrary redirection.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-004</p>
    <p><strong>Description:</strong> Client-side open redirects occur when JavaScript or HTML uses unvalidated user input to redirect users to external domains, potentially enabling phishing attacks.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Scan for redirect parameters in URLs and JavaScript code.</p>
    <p>4. Inject redirect payloads such as <code>redirect=https://example.com</code>.</p>
    <p>5. Monitor browser navigation and capture redirect behavior.</p>
    <p>6. Verify if external domains are reachable via redirect.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Client-Side Open Redirect</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Parameter Tested:</strong> <code>redirect</code></p>
    <p><strong>Payload Used:</strong> <code>https://example.com</code></p>
    <pre>[Redirect URL: http://localhost/dvwa/vulnerabilities/redirect/?to=https://example.com]
[Final Destination: https://example.com]</pre>
    <p class="evidence"><strong>Evidence:</strong> Browser successfully redirected to external domain.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can craft malicious links that appear to come from a trusted domain but redirect users to phishing sites, malware distribution points, or scam pages. This can lead to credential theft and loss of trust in the legitimate application.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Avoid using user-controllable data in redirect locations.</p>
    <p class="recommendation">- Use a whitelist of allowed domains for redirection.</p>
    <p class="recommendation">- Implement server-side validation of redirect targets.</p>
    <p class="recommendation">- Replace direct URL redirects with ID-based mapping (e.g., redirect=1 → homepage).</p>
    <p class="recommendation">- Add user confirmation before external redirects.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>