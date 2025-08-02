# AI Coding Agent Prompt: Web Messaging (OTG-CLIENT-011) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that **analyzes** `http://localhost/dvwa/` for potential **Web Messaging** vulnerabilities as part of testing **OTG-CLIENT-011 – Testing Web Messaging**. Since **DVWA does not implement the `postMessage()` API** or cross-origin communication, the script must perform a **diagnostic scan** to confirm the absence of Web Messaging functionality and generate a professional, well-structured **OWASP/OSCP-style HTML report** that explains:

- What Web Messaging is (via `window.postMessage()`)
- Why it's not present in DVWA
- The security implications of insecure message handling
- Common vulnerabilities (origin validation, message tampering)
- Recommendations for secure implementation
- Educational context about modern cross-document communication

> **Note**: This script is **not expected to demonstrate active Web Messaging exploitation**, as DVWA is a traditional PHP application without `postMessage()` usage. Instead, it should serve as an **educational and compliance-focused tool** to verify the absence of Web Messaging and document the risk landscape.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Not applicable (Web Messaging testing is independent of DVWA security levels)
- Test relevant endpoints:
  - `/`
  - `/login.php`
  - `/vulnerabilities/xss_r/`
  - `/vulnerabilities/xss_s/`
  - `/vulnerabilities/sqli/`
  - `/vulnerabilities/csrf/`

### 2. **Testing Objective: OTG-CLIENT-011 – Testing Web Messaging**
- **Goal**: Confirm that DVWA does **not** use `window.postMessage()` or `addEventListener('message', ...)` for cross-document communication
- **Check for**:
  - `postMessage()` calls in JavaScript
  - `message` event listeners (`window.addEventListener('message', ...)`)
  - Insecure origin validation (e.g., `if (event.origin !== "https://evil.com")`)
  - Message data reflection in DOM (XSS risk)
  - Iframes from different origins that might communicate
- **Analyze results**:
  - No Web Messaging functionality should be found
  - Document that DVWA is a single-origin application
  - Explain that modern SPAs often use `postMessage()` for secure cross-origin communication
- **Educational Note**: While Web Messaging enables legitimate cross-origin communication, insecure implementations can lead to:
  - Cross-site scripting (XSS)
  - Information disclosure
  - Privilege escalation
  - CSRF via trusted message channels

### 3. **Automation Requirements**
- Use `requests` to fetch and parse HTML/JS content from DVWA endpoints
- Use `BeautifulSoup` to search for:
  - `postMessage(` patterns in JavaScript
  - `addEventListener('message'` or `onmessage` handlers
  - `event.origin` checks
  - `event.data` usage in DOM manipulation
- Search response bodies for Web Messaging-related strings
- Use **Selenium** to:
  - Execute JavaScript and check for `postMessage` API usage
  - Verify no message listeners are registered
- Handle login via CSRF token extraction
- Log all findings and evidence

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-011_Report.html` file with the following structure and styling:

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
    .safe { color: #55FF55; }
    .info { color: #55AAFF; }
    footer { margin-top: 60px; font-size: 0.8em; text-align: center; color: #666; }
    code { background: #333; padding: 2px 4px; border-radius: 3px; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p><strong>Test ID:</strong> OTG-CLIENT-011</p>
    <p><strong>Vulnerability:</strong> Web Messaging Security</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Determine if the application uses insecure Web Messaging via <code>postMessage()</code>.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-011</p>
    <p><strong>Note:</strong> DVWA is a traditional server-rendered PHP application without cross-origin communication. This test confirms the absence of Web Messaging implementation.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Scan all pages for <code>postMessage()</code> and message event listeners.</p>
    <p>3. Analyze JavaScript for insecure message handling.</p>
    <p>4. Use Selenium to verify no message listeners are active.</p>
    <p>5. Confirm no Web Messaging functionality is present.</p>
    <p>6. Document findings and security posture.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Web Messaging Implementation</h3>
    <p><strong>Status:</strong> <span class="safe">Not Applicable (Web Messaging Not Used)</span></p>
    <pre>[Endpoint: /vulnerabilities/xss_s/]
Search Results:
  postMessage() calls: 0
  message event listeners: 0
  event.origin checks: 0
  insecure data handling: 0</pre>
    <p class="evidence"><strong>Evidence:</strong> No Web Messaging functionality was found in DVWA. The application does not use cross-document messaging APIs.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>Since DVWA does not use Web Messaging, there is no risk of postMessage-related vulnerabilities such as origin validation bypass, message injection, or DOM-based XSS via message data. However, this also means DVWA cannot be used to practice real-world Web Messaging security testing.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- When using <code>postMessage()</code>, always validate the <code>event.origin</code>.</p>
    <p class="recommendation">- Avoid using <code>*</code> as the targetOrigin parameter.</p>
    <p class="recommendation">- Sanitize message data before using it in the DOM.</p>
    <p class="recommendation">- Implement proper error handling for message events.</p>
    <p class="recommendation">- For learning Web Messaging security, use platforms like PortSwigger Academy or WebGoat.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>