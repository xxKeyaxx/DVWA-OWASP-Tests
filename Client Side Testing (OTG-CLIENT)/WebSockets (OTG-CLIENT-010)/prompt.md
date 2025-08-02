# AI Coding Agent Prompt: WebSockets (OTG-CLIENT-010) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that **analyzes** `http://localhost/dvwa/` for potential **WebSocket** functionality as part of testing **OTG-CLIENT-010 – Testing WebSockets**. Since **DVWA does not implement WebSockets**, the script must perform a **diagnostic scan** to confirm the absence of WebSocket endpoints and generate a professional, well-structured **OWASP/OSCP-style HTML report** that explains:

- What WebSockets are
- Why they're not present in DVWA
- The security implications of WebSocket vulnerabilities
- Recommendations for secure WebSocket implementation
- Educational context about modern real-time web applications

> **Note**: This script is **not expected to demonstrate active WebSocket exploitation**, as DVWA is a traditional PHP application without real-time features. Instead, it should serve as an **educational and compliance-focused tool** to verify the absence of WebSockets and document the risk landscape.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Not applicable (WebSocket testing is independent of DVWA security levels)
- Test relevant endpoints:
  - `/`
  - `/login.php`
  - `/vulnerabilities/xss_r/`
  - `/vulnerabilities/xss_s/`
  - `/vulnerabilities/sqli/`
  - `/vulnerabilities/csrf/`

### 2. **Testing Objective: OTG-CLIENT-010 – Testing WebSockets**
- **Goal**: Confirm that DVWA does **not** use WebSocket (`ws://` or `wss://`) communication
- **Check for**:
  - WebSocket connections in JavaScript (`new WebSocket("ws://...")`)
  - Presence of `Upgrade: websocket` HTTP headers
  - `Sec-WebSocket-Key` and related headers
  - JavaScript that uses `onmessage`, `onopen`, `onerror` for WebSocket events
  - References to WebSocket libraries or frameworks
- **Analyze results**:
  - No WebSocket functionality should be found
  - Document that DVWA is a traditional request-response application
  - Explain that modern real-time apps use WebSockets, but DVWA does not
- **Educational Note**: While WebSockets enable powerful real-time features, they also introduce security risks like message injection, authentication bypass, and CSRF if not properly implemented

### 3. **Automation Requirements**
- Use `requests` to fetch and parse HTML/JS content from DVWA endpoints
- Use `BeautifulSoup` to search for:
  - `new WebSocket(` patterns in JavaScript
  - WebSocket event handlers (`onmessage`, `onopen`)
  - References to WebSocket libraries
- Search response bodies for WebSocket-related strings
- Check HTTP response headers for WebSocket upgrade attempts
- Do **not** require Selenium unless needed for login (use `requests` session)
- Handle login via CSRF token extraction
- Log all findings and evidence
- Optionally attempt to connect to common WebSocket ports (e.g., `ws://localhost:8080`) to check for separate WebSocket servers

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-010_Report.html` file with the following structure and styling:

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
    <p><strong>Test ID:</strong> OTG-CLIENT-010</p>
    <p><strong>Vulnerability:</strong> WebSockets Security</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Determine if the application uses WebSockets for real-time communication.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-010</p>
    <p><strong>Note:</strong> DVWA is a traditional server-rendered PHP application without real-time features. This test confirms the absence of WebSocket implementation.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Scan all pages for WebSocket-related JavaScript code.</p>
    <p>3. Analyze HTTP headers for WebSocket upgrade attempts.</p>
    <p>4. Attempt to connect to common WebSocket ports.</p>
    <p>5. Confirm no WebSocket functionality is present.</p>
    <p>6. Document findings and security posture.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>WebSocket Implementation</h3>
    <p><strong>Status:</strong> <span class="safe">Not Applicable (WebSockets Not Used)</span></p>
    <pre>[Endpoint: /vulnerabilities/xss_s/]
Search Results:
  new WebSocket() calls: 0
  onmessage handlers: 0
  WebSocket-related strings: 0
  Upgrade headers: Not Present</pre>
    <p class="evidence"><strong>Evidence:</strong> No WebSocket functionality was found in DVWA. The application uses traditional request-response patterns without real-time communication.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>Since DVWA does not use WebSockets, there is no risk of WebSocket-specific vulnerabilities such as message injection, authentication bypass, or cross-site WebSocket hijacking. However, this also means DVWA cannot be used to practice real-world WebSocket security testing.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- For applications requiring real-time features, implement WebSockets securely.</p>
    <p class="recommendation">- Validate and sanitize all WebSocket messages on the server side.</p>
    <p class="recommendation">- Implement proper authentication and authorization for WebSocket connections.</p>
    <p class="recommendation">- Use WSS (WebSocket Secure) instead of WS.</p>
    <p class="recommendation">- Protect against Cross-Site WebSocket Hijacking (CSWSH) with origin validation.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>