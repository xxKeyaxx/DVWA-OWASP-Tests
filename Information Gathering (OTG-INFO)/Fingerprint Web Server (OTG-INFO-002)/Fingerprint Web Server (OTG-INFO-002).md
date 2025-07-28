# AI Prompt: Web Server Fingerprint Tester for DVWA

## Objective
Create a Python script to test Fingerprint Web Server (OTG-INFO-002) vulnerability on DVWA running at `http://localhost/dvwa/` via XAMPP. Generate an OWASP-style HTML report.

## Requirements

### Target Environment
- **URL**: `http://localhost/dvwa/`
- **Authentication**: Handle login to DVWA (default: admin/password)
- **Security Level**: Set to "low" (script should handle login session)

### Test Specifications
1. **Header Analysis**:
   - Capture `Server`, `X-Powered-By`, and other identifying headers
   - Analyze HTTP response headers via HEAD and GET requests

2. **Common Files Check**:
   - Test for existence of:
     - `/server-status`
     - `/server-info`
     - `/phpinfo.php`
     - `/test.php`
     - `.well-known/security.txt`

3. **Banner Grabbing**:
   - Perform socket connection to port 80
   - Send malformed requests to trigger error pages
   - Analyze default error pages for server signatures

4. **Framework Detection**:
   - Check for framework-specific files:
     - `/README.md`
     - `/CHANGELOG.txt`
     - Framework-specific cookies/headers

### Report Requirements
- **OWASP Format** in HTML with:
  ```html
  <!-- Required Sections -->
  <section id="executive-summary">...</section>
  <section id="test-details">...</section>
  <section id="findings">...</section>
  <section id="risk-assessment">...</section>
  <section id="recommendations">...</section>
  <section id="evidence">...</section>