# AI Coding Agent Prompt: Cross-Site Flashing (OTG-CLIENT-008) Test Script & OSCP-Style Report for DVWA

## Objective

Create a Python script that **analyzes** `http://localhost/dvwa/` for potential **Cross-Site Flashing (OTG-CLIENT-008)** vulnerabilities, despite the fact that **Adobe Flash is deprecated and not used in DVWA**. The script must perform a **diagnostic scan** to confirm the absence of Flash content and generate a professional, well-structured **OWASP/OSCP-style HTML report** that explains:

- What Cross-Site Flashing is
- Why it's obsolete
- That DVWA does not use Flash
- The security implications for modern applications
- Recommendations for secure development

> **Note**: This script is **not expected to demonstrate active Flash exploitation**, as DVWA does not contain `.swf` files or Flash-based components. Instead, it should serve as an **educational and compliance-focused tool** to verify the absence of Flash and document the risk landscape.

---

## Prompt for AI Coding Agent

> You are an advanced AI security automation assistant. Your task is to generate a complete Python script that performs the following:

### 1. **Target Environment**
- The target is `http://localhost/dvwa/`
- DVWA is running via XAMPP with login credentials:
  - Username: `admin`
  - Password: `password`
- Security level: Not applicable (Flash testing is independent of DVWA security levels)
- Test relevant endpoints:
  - `/`
  - `/login.php`
  - `/vulnerabilities/xss_r/`
  - `/vulnerabilities/xss_s/`
  - `/vulnerabilities/sqli/`
  - `/vulnerabilities/csrf/`

### 2. **Testing Objective: OTG-CLIENT-008 – Cross-Site Flashing**
- **Goal**: Confirm that DVWA does **not** use Adobe Flash (`.swf`) files or related technologies
- **Check for**:
  - `.swf` file references in HTML/JS
  - `<object>`, `<embed>`, or `<applet>` tags with Flash content
  - JavaScript that uses `ActiveXObject` or Flash detection scripts
  - MIME types indicating Flash (`application/x-shockwave-flash`)
- **Analyze results**:
  - No Flash content should be found
  - Document that Flash is deprecated (EOL: December 2020)
  - Explain that modern browsers no longer support Flash
- **Educational Note**: While Cross-Site Flashing was a real vulnerability class in the past, it is now **obsolete** due to Flash deprecation

### 3. **Automation Requirements**
- Use `requests` to fetch and parse HTML/JS content from DVWA endpoints
- Use `BeautifulSoup` to search for:
  - `<object type="application/x-shockwave-flash">`
  - `<embed src="*.swf">`
  - `<param name="movie" value="...">`
  - Flash detection scripts (e.g., `swfobject.js`, `hasFlash()`)
- Search response bodies for `.swf` strings
- Do **not** require Selenium unless needed for login (use `requests` session)
- Handle login via CSRF token extraction
- Log all findings and evidence

### 4. **Output: OSCP/OWASP-Style HTML Report**
Generate a standalone `OTG-CLIENT-008_Report.html` file with the following structure and styling:

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
    <p><strong>Test ID:</strong> OTG-CLIENT-008</p>
    <p><strong>Vulnerability:</strong> Cross-Site Flashing</p>
    <p><strong>Target:</strong> http://localhost/dvwa/</p>
    <p><strong>Date:</strong> [CURRENT DATE]</p>
  </div>

  <div class="section">
    <h2>1. Test Overview</h2>
    <p><strong>Objective:</strong> Determine if the application uses Adobe Flash in a way that could be exploited via Cross-Site Flashing.</p>
    <p><strong>OWASP Reference:</strong> OTG-CLIENT-008</p>
    <p><strong>Note:</strong> Adobe Flash reached end-of-life on December 31, 2020. Modern browsers no longer support Flash. This test confirms its absence in DVWA.</p>
  </div>

  <div class="section">
    <h2>2. Test Procedure</h2>
    <p>1. Authenticate to DVWA using provided credentials.</p>
    <p>2. Scan all pages for <code>.swf</code> references and Flash-related HTML tags.</p>
    <p>3. Analyze JavaScript for Flash detection or interaction.</p>
    <p>4. Confirm no Flash content is present.</p>
    <p>5. Document findings and security posture.</p>
  </div>

  <div class="section">
    <h2>3. Findings</h2>
    <h3>Cross-Site Flashing (OTG-CLIENT-008)</h3>
    <p><strong>Status:</strong> <span class="safe">Not Applicable (Flash Not Used)</span></p>
    <pre>[Endpoint: /vulnerabilities/xss_s/]
Search Results:
  .swf references: 0
  <object> tags: 0
  <embed> tags: 0
  Flash detection scripts: 0</pre>
    <p class="evidence"><strong>Evidence:</strong> No Flash content or related technologies were found. Adobe Flash is deprecated and should not be used in modern applications.</p>
  </div>

  <div class="section">
    <h2>4. Impact</h2>
    <p>Since DVWA does not use Adobe Flash, there is no risk of Cross-Site Flashing attacks. However, this also means DVWA cannot be used to practice real-world Flash-based vulnerability testing.</p>
  </div>

  <div class="section">
    <h2>5. Recommendations</h2>
    <p class="recommendation">- Do not use Adobe Flash in any new or existing applications.</p>
    <p class="recommendation">- Migrate legacy Flash content to HTML5, WebAssembly, or modern JavaScript frameworks.</p>
    <p class="recommendation">- Audit third-party libraries for hidden Flash dependencies.</p>
    <p class="recommendation">- For learning historical vulnerabilities, use archived platforms like Google Gruyere.</p>
  </div>

  <footer>
    &copy; 2025 Automated Security Testing Framework. Report generated by AI Agent.
  </footer>
</body>
</html>