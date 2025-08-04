# AI Coding Agent Prompt: HTML Injection (OTG-CLIENT-003) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that automates testing for **HTML Injection (OTG-CLIENT-003)** on a local instance of **Damn Vulnerable Web Application (DVWA)** running via **XAMPP on localhost**. The script must detect and demonstrate client-side HTML injection vulnerabilities (e.g., in input fields that allow raw HTML) and generate a professional, well-structured **OWASP/OSCP-style HTML report** styled to resemble official penetration testing reports.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Set to **Low** (automatically configure via script if possible)
- Test relevant modules: **XSS (Reflected)**, **XSS (Stored)**, and any other input fields that render user content

### 2. **Testing Objective: OTG-CLIENT-003 – HTML Injection**
- Identify input fields vulnerable to **HTML injection** (distinct from JavaScript execution).
- Inject benign HTML payloads such as:
  - `<h1 style="color:red;">INJECTED HTML</h1>`
  - `<img src="nonexistent.jpg" onerror="alert('HTML Injection')"/>`
  - `<b>Bold Text via Injection</b>` or `<p><i>Italic Paragraph</i></p>`
- Confirm injection by:
  - Parsing the response to detect presence of injected HTML
  - Using browser automation to verify rendering
  - Avoid triggering aggressive alerts unless necessary

### 3. **Automation Requirements**
- Use `selenium` for browser interaction and DOM inspection.
- Use `requests` and `BeautifulSoup` for session handling and form parsing.
- Automate login to DVWA.
- Navigate to relevant pages (XSS Reflected and Stored).
- Submit HTML-only payloads (avoid malicious scripts).
- Extract and validate response content for injected HTML.
- Handle CSRF tokens (`user_token`) dynamically.
- Ensure payloads do **not** cause persistent damage or aggressive popups.

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-003_Report.html` file with the following structure and styling:

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
    <p><strong>Test ID:</strong> OTG-CLIENT-003</p>
    <p><strong>Vulnerability:</strong> HTML Injection</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify HTML injection vulnerabilities in user input fields.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-003</p>
    <p><strong>Description:</strong> HTML Injection occurs when user input is embedded in the page output without proper sanitization, allowing attackers to inject visible HTML content.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Navigate to vulnerable input forms (e.g., XSS Reflected/Stores).</p>
    <p>4. Inject HTML payloads such as <code><h1></code>, <code><b></code>, <code><img></code>.</p>
    <p>5. Capture server responses and DOM state.</p>
    <p>6. Verify rendering via browser automation.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Reflected HTML Injection</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Payload Used:</strong> <code><h1 style="color:red;">INJECTED HTML</h1></code></p>
    <pre>[Response snippet showing injected HTML]</pre>
    <p class="evidence"><strong>Evidence:</strong> Injected heading rendered in response.</p>

    <h3>Stored HTML Injection</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Payload Used:</strong> <code><img src="x" onerror="alert('HTML Injection')"></code></p>
    <pre>[Stored content snippet]</pre>
    <p class="evidence"><strong>Evidence:</strong> Image error handler executed on page load.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can alter the visual appearance of the web page, potentially misleading users, injecting fake forms, or redirecting clicks. While less severe than XSS, it can be used for phishing and UI redressing.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Sanitize all user inputs using libraries like DOMPurify or OWASP Java Encoder.</p>
    <p class="recommendation">- Implement proper output encoding based on context (HTML, HTML attribute, JS, CSS, URL).</p>
    <p class="recommendation">- Use Content Security Policy (CSP) to restrict inline scripts and unauthorized resources.</p>
    <p class="recommendation">- Validate input length, format, and allowed HTML tags if rich text is required.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>