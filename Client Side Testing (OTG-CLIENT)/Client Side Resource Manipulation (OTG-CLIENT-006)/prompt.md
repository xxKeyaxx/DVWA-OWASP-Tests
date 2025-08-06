# AI Coding Agent Prompt: Client-Side Resource Manipulation (OTG-CLIENT-006) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that automates testing for **Client-Side Resource Manipulation (OTG-CLIENT-006)** on a local instance of **Damn Vulnerable Web Application (DVWA)** running via **XAMPP on localhost**. The script must detect and demonstrate vulnerabilities where user input controls the loading of client-side resources (e.g., scripts, iframes, images) and generate a professional, well-structured **OWASP/OSCP-style HTML report** styled to resemble official penetration testing reports.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Set to **Low** (automatically configure via script if possible)
- Test relevant modules: 
  - XSS (Reflected) – `/vulnerabilities/xss_r/`
  - XSS (Stored) – `/vulnerabilities/xss_s/`
  - Any input fields that render user content

### 2. **Testing Objective: OTG-CLIENT-006 – Client-Side Resource Manipulation**
- Identify input fields vulnerable to **resource manipulation** where user input controls:
  - `<script src="[user_input]">`
  - `<iframe src="[user_input]">`
  - `<img src="[user_input]">`
  - `XMLHttpRequest` or `fetch()` with user-controlled URLs
- Inject benign but detectable payloads such as:
  - `<script src="http://localhost/test.js"></script>` 
  - `<iframe src="javascript:alert('Resource Manipulation')"></iframe>`
  - `<img src="http://localhost/track.gif?c='+document.cookie+'" />`
- Confirm manipulation by:
  - Parsing the response to detect injected resource tags
  - Using browser automation to verify resource loading
  - Monitoring network requests (if possible via DevTools Protocol)
- Focus on **dynamic resource loading** controlled by user input, as described in the DVWA documentation

### 3. **Automation Requirements**
- Use `selenium` for browser automation and DOM/network inspection
- Use `requests` and `BeautifulSoup` for session handling and form parsing
- Automate login to DVWA
- Set security level to **Low**
- Navigate to relevant pages (XSS Reflected and Stored)
- Submit resource manipulation payloads
- Extract and validate response content for injected resource tags
- Handle CSRF tokens (`user_token`) dynamically
- Ensure payloads do **not** cause permanent damage or aggressive popups
- Properly HTML-encode payloads in the report to prevent self-injection

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-006_Report.html` file with the following structure and styling:

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
    <p><strong>Test ID:</strong> OTG-CLIENT-006</p>
    <p><strong>Vulnerability:</strong> Client-Side Resource Manipulation</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify if user input can control the loading of client-side resources.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-006</p>
    <p><strong>Description:</strong> Client-Side Resource Manipulation occurs when user input is used to specify the source of resources like scripts, iframes, or images, potentially leading to XSS or data exfiltration.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Navigate to vulnerable input forms (e.g., XSS Reflected/Stores).</p>
    <p>4. Inject resource manipulation payloads such as <code><script src="..."></code>, <code><iframe src="..."></code>.</p>
    <p>5. Capture server responses and DOM state.</p>
    <p>6. Verify resource loading via browser automation.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Reflected Resource Manipulation</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Payload Used:</strong> <code><script src="http://localhost/test.js"></script></code></p>
    <pre>[Response snippet showing injected script tag]</pre>
    <p class="evidence"><strong>Evidence:</strong> External script source reflected in response and loaded.</p>

    <h3>Stored Resource Manipulation</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Payload Used:</strong> <code><img src="http://localhost/track.gif" /></code></p>
    <pre>[Stored content snippet]</pre>
    <p class="evidence"><strong>Evidence:</strong> Image loaded from manipulated source.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can manipulate resource loading to execute malicious scripts, exfiltrate data, or redirect users to phishing sites. This can lead to full account compromise when combined with XSS.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Sanitize user inputs to remove or encode resource-related attributes.</p>
    <p class="recommendation">- Implement proper output encoding based on context.</p>
    <p class="recommendation">- Use Content Security Policy (CSP) to restrict resource loading.</p>
    <p class="recommendation">- Avoid using user input in resource URLs.</p>
    <p class="recommendation">- Validate and filter input for resource manipulation patterns.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>