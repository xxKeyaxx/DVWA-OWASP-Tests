# AI Coding Agent Prompt: Clickjacking (OTG-CLIENT-009) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that automates testing for **Clickjacking (OTG-CLIENT-009)** on a local instance of **Damn Vulnerable Web Application (DVWA)** running via **XAMPP on localhost**. The script must detect the absence of anti-framing protections, generate a **proof-of-concept (PoC) clickjacking page**, and produce a professional, well-structured **OWASP/OSCP-style HTML report** styled to resemble official penetration testing reports.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Not applicable (clickjacking is independent of security level)
- Test relevant modules: 
  - `/vulnerabilities/csrf/` (ideal for clickjacking due to sensitive action)
  - `/security.php` (common target)
  - `/` (main dashboard)

### 2. **Testing Objective: OTG-CLIENT-009 – Clickjacking**
- Identify whether DVWA can be embedded in an `<iframe>` (i.e., **framed**) by checking for the absence of:
  - `X-Frame-Options` HTTP header
  - `Content-Security-Policy: frame-ancestors` directive
- Confirm vulnerability by:
  - Analyzing HTTP response headers from key DVWA pages
  - Generating a working **proof-of-concept (PoC) HTML file** that embeds a sensitive DVWA page (e.g., CSRF password change)
  - Overlaying fake UI elements (e.g., "Click to Win!" button) over legitimate buttons
- The PoC should demonstrate how a user could be tricked into performing unintended actions

### 3. **Automation Requirements**
- Use `requests` to fetch HTTP headers from DVWA endpoints
- Do **not** require Selenium for the main test (clickjacking detection is header-based)
- Generate a standalone `clickjacking_poc.html` file that:
  - Embeds `http://localhost/dvwa/vulnerabilities/csrf/` in a transparent iframe
  - Positions a fake button over the real "Change" button
  - Uses CSS to make the iframe nearly invisible (`opacity: 0.01`)
  - Is self-contained (no external dependencies)
- The script should:
  - Log all findings
  - Save the PoC file in the current directory
  - Include the PoC filename in the final report

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-009_Report.html` file with the following structure and styling:

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
    <p><strong>Test ID:</strong> OTG-CLIENT-009</p>
    <p><strong>Vulnerability:</strong> Clickjacking</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect the ability to embed DVWA pages in an iframe to trick users into performing unintended actions.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-009</p>
    <p><strong>Description:</strong> Clickjacking occurs when a vulnerable web page can be framed, allowing an attacker to overlay invisible UI elements and hijack user clicks.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Send HTTP requests to key DVWA endpoints.</p>
    <p>2. Analyze response headers for <code>X-Frame-Options</code> and <code>Content-Security-Policy</code>.</p>
    <p>3. Confirm absence of anti-framing protections.</p>
    <p>4. Generate a proof-of-concept (PoC) HTML file demonstrating the vulnerability.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Clickjacking Vulnerability</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Affected Pages:</strong> /vulnerabilities/csrf/, /security.php, /</p>
    <pre>HTTP/1.1 200 OK
Date: Mon, 02 Aug 2025 12:00:00 GMT
Server: Apache/2.4.41 (Unix)
Content-Type: text/html; charset=UTF-8
... [No X-Frame-Options or CSP frame-ancestors] ...</pre>
    <p class="evidence"><strong>Evidence:</strong> No anti-framing headers detected. Proof-of-concept generated: <code>clickjacking_poc.html</code></p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can embed DVWA pages in a malicious site and trick logged-in users into performing sensitive actions (e.g., changing password, altering security settings) without their knowledge. This can lead to full account compromise.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Add <code>X-Frame-Options: DENY</code> or <code>SAMEORIGIN</code> header.</p>
    <p class="recommendation">- Implement <code>Content-Security-Policy: frame-ancestors 'none'</code> or <code>'self'</code>.</p>
    <p class="recommendation">- Test all sensitive pages for framing vulnerability.</p>
    <p class="recommendation">- Educate users about suspicious page behavior.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>