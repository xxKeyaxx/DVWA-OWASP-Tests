# AI Prompt: Configuration & Deployment Testing (OTG-CONFIG) for DVWA

## Objective
Python script to perform OTG-CONFIG-002 to 008 tests on DVWA (`http://localhost/dvwa/`) and generate OWASP-style HTML report.

## Updates to Match Implementation
### Environment Configuration
- Added security token handling in authentication
- Implemented rate limiting with `sleep()` between requests
- Added comprehensive error handling with tracebacks

### Test Enhancements
1. **OTG-CONFIG-002 (Platform Config):**
   - Added SQL error trigger test
   - Debug mode detection patterns: `debug=true` and `debug_mode=on`
   - Added 3 test cases with specific error triggers

2. **OTG-CONFIG-003 (File Extensions):**
   - Extended extensions: `.inc`, `.config`, `.env`, `.swp`, `.tmp`, `.log`, `.sql`, `.yml`
   - Added source code detection: PHP tags (`<?php`) and "Configuration" keywords
   - Tested files: `index.php`, `login.php`, `setup.php`, `.htaccess`, `config.inc.php`

3. **OTG-CONFIG-004 (Backup Files):**
   - Added patterns: `.backup`, `_backup`, `.tar.gz`
   - Sensitive content detection: "password", "database", "user", "secret", "key"
   - Core files tested: `index.php`, `login.php`, `setup.php`, `config.inc.php`

4. **OTG-CONFIG-005 (Admin Interfaces):**
   - Added paths: `/manager/`, `/webadmin/`
   - Authentication check: "login", "username", "password" in response
   - Risk adjustment: Unprotected interfaces → High risk

5. **OTG-CONFIG-006 (HTTP Methods):**
   - Test URL: `/vulnerabilities/upload/`
   - Added OPTIONS method pre-check
   - Verification of actual method execution (PUT/DELETE/TRACE)

6. **OTG-CONFIG-007 (HSTS):**
   - Added HTTPS fallback test
   - Handled SSL errors gracefully
   - HTTP-only environment detection

7. **OTG-CONFIG-008 (Cross Domain):**
   - Added `/clientaccesspolicy.xml` check
   - Permissive policy detection: 
     - `allow-access-from domain="*"`
     - `<allow-http-request-headers-from domain="*">`

### Reporting Features
- Dynamic risk labeling (High/Medium/Low/Info)
- Test status badges (Success/Failed)
- Collapsible evidence sections
- Syntax-highlighted evidence previews
- Responsive mobile-friendly design
- Error traceback display for failed tests
- Visual risk indicators:
  - High: Red
  - Medium: Yellow
  - Low: Green
  - Info: Blue

### Terminal Output Updates