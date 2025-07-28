# AI Prompt: Web Application Enumeration Tester for DVWA

## Objective
Create a Python script to test Enumerate Applications on Web Server (OTG-INFO-004) vulnerability on DVWA running at `http://localhost/dvwa/` via XAMPP. Generate an OWASP-style HTML report that integrates with the previous Fingerprint Web Server report.

## Requirements

### Target Environment
- **URL**: `http://localhost/dvwa/`
- **Authentication**: Reuse login mechanism from previous script (admin/password)
- **Security Level**: Maintain "low" security level
- **Session Handling**: Persist cookies across requests

### Test Specifications
1. **Common Directory Enumeration**:
   - Test for existence of common directories:
     - `/admin/`, `/backup/`, `/config/`, `/install/`, `/logs/`
     - `/includes/`, `/uploads/`, `/assets/`
     - Framework-specific directories (e.g., `/wp-admin/`, `/drupal/`)

2. **Common File Discovery**:
   - Check for sensitive files:
     - `robots.txt`, `crossdomain.xml`, `security.txt`
     - `web.config`, `.htaccess`, `.env`
     - Backup files (`*.bak`, `*.old`, `*.zip`)
     - Version control files (`.git/HEAD`, `.svn/entries`)

3. **Common Application Detection**:
   - Test for admin interfaces:
     - `/phpmyadmin/`, `/adminer.php`, `/mysql/`
   - Check for development files:
     - `test.php`, `info.php`, `console.php`
   - Scan for install/uninstall scripts

4. **Content Discovery**:
   - Identify HTML comments revealing application details
   - Detect hidden form fields
   - Check for exposed metadata in:
     - `/package.json`, `/composer.json`, `/bower.json`

### Report Integration Requirements
- **Unified HTML Report**: Append to existing `OWASP_Web_Server_Fingerprint_Report.html`
- **New Sections**:
  ```html
  <section id="application-enumeration">
    <h2>OTG-INFO-004: Application Enumeration</h2>
    <!-- Findings structure -->
    <div class="finding">
      <h3>{Finding Title}</h3>
      <p><strong>Path</strong>: {URL}</p>
      <p><strong>Status Code</strong>: {HTTP Status}</p>
      <pre>{Response Snippet}</pre>
    </div>
  </section>