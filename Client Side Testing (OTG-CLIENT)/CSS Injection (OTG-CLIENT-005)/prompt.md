# AI Coding Agent Prompt: CSS Injection (OTG-CLIENT-005) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that automates testing for **CSS Injection (OTG-CLIENT-005)** on a local instance of **Damn Vulnerable Web Application (DVWA)** running via **XAMPP on localhost**. The script must detect and demonstrate client-side CSS injection vulnerabilities and generate a professional, well-structured **OWASP/OSCP-style HTML report** styled to resemble official penetration testing reports.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Set to **Low** (automatically configure via script if possible)
- Test relevant modules: Any input fields that render user content (e.g., **XSS (Reflected)**, **XSS (Stored)**, comment sections)

### 2. **Testing Objective: OTG-CLIENT-005 – CSS Injection**
- Identify input fields vulnerable to **CSS injection** where user input is embedded in style attributes or style tags without proper sanitization
- Inject benign CSS payloads such as:
  - `<style>body { background-color: red !important; }</style>`
  - `<p style="color: green; font-size: 24px;">Injected via CSS</p>`
  - `"><img src=x onerror=alert('CSS Injection')>` (to test CSS context XSS)
- Confirm injection by:
  - Parsing the response to detect presence of injected CSS
  - Using browser automation to verify visual rendering changes
  - Capturing DOM state before and after injection
- Focus on **pure CSS injection** (visual manipulation) rather than CSS-based XSS, though note if CSS contexts allow script execution

### 3. **Automation Requirements**
- Use `selenium` for browser interaction and visual/DOM verification
- Use `requests` and `BeautifulSoup` for session handling and form parsing
- Automate login to DVWA
- Set security level to **Low**
- Navigate to relevant pages (e.g., XSS Reflected and Stored)
- Submit CSS injection payloads
- Extract and validate response content for injected CSS
- Handle CSRF tokens (`user_token`) dynamically
- Ensure payloads do **not** cause permanent damage or aggressive popups
- Verify if CSS injection leads to information disclosure (e.g., via `:visited` selectors in older browsers) or UI redressing

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-005_Report.html` file with the following structure and styling:

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
    <p><strong>Test ID:</strong> OTG-CLIENT-005</p>
    <p><strong>Vulnerability:</strong> CSS Injection</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Detect and verify CSS injection vulnerabilities in user input fields.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-005</p>
    <p><strong>Description:</strong> CSS Injection occurs when user input is embedded in CSS contexts without proper sanitization, allowing attackers to manipulate page styling and potentially extract information.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Set security level to <strong>Low</strong>.</p>
    <p>3. Navigate to vulnerable input forms (e.g., XSS Reflected/Stores).</p>
    <p>4. Inject CSS payloads such as <code><style></code>, <code>style=""</code> attributes.</p>
    <p>5. Capture server responses and DOM state.</p>
    <p>6. Verify visual rendering via browser automation.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Reflected CSS Injection</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Payload Used:</strong> <code><style>body {{ background-color: red !important; }}</style></code></p>
    <pre>[Response snippet showing injected CSS]</pre>
    <p class="evidence"><strong>Evidence:</strong> Page background color changed to red.</p>

    <h3>Stored CSS Injection</h3>
    <p><strong>Status:</strong> <span class="vulnerable">Vulnerable</span></p>
    <p><strong>Payload Used:</strong> <code><p style="color: green;">Injected via CSS</p></code></p>
    <pre>[Stored content snippet]</pre>
    <p class="evidence"><strong>Evidence:</strong> Green text rendered in stored content.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>An attacker can alter the visual appearance of the web page, potentially leading to UI redressing, phishing, or information disclosure through CSS pseudo-selectors. While less severe than XSS, it can be used in conjunction with other vulnerabilities.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Sanitize user inputs to remove or encode CSS-related keywords and tags.</p>
    <p class="recommendation">- Implement proper output encoding based on context (HTML, CSS, attribute).</p>
    <p class="recommendation">- Use Content Security Policy (CSP) to restrict inline styles and external stylesheets.</p>
    <p class="recommendation">- Avoid using user input in style attributes or style blocks.</p>
    <p class="recommendation">- Validate and filter input for CSS-specific patterns (e.g., {, }, style=, <style>).</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>