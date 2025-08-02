# AI Prompt: Comprehensive Web Application Analysis Suite

## Objective
Create a Python script to perform advanced web application analysis on DVWA (http://localhost/dvwa/) including:
1. Identify Application Entry Points (OTG-INFO-006)
2. Map Execution Paths (OTG-INFO-007)
3. Fingerprint Web Application Framework (OTG-INFO-008)
4. Fingerprint Web Application (OTG-INFO-009)
5. Map Application Architecture (OTG-INFO-010)
6. Generate an OWASP-style HTML report that integrates with the previous OTG-INFO

## Requirements

### Target Environment
- **URL**: `http://localhost/dvwa/`
- **Authentication**: Reuse login mechanism from previous scripts
- **Security Level**: Maintain "low" security level
- **Session Handling**: Persistent cookies across requests

### Test Specifications

#### 1. Application Entry Points (OTG-INFO-006)
- Crawl all accessible pages starting from index
- Identify all input vectors:
  - HTML forms (method, action, parameters)
  - URL parameters (GET)
  - AJAX endpoints (XHR requests)
  - File upload points
- Map hidden parameters and non-standard input types

#### 2. Execution Path Mapping (OTG-INFO-007)
- Trace state transitions through:
  - Authentication flows
  - Privilege escalation paths
  - Session-dependent workflows
- Identify parameter dependencies
- Detect broken access control paths

#### 3. Framework Fingerprinting (OTG-INFO-008)
- Detect framework via:
  - HTML meta tags and generator headers
  - Framework-specific cookies
  - JavaScript library patterns
  - File/directory conventions
- Framework detection database:
  ```python
  FRAMEWORK_SIGNATURES = {
      'Laravel': {'files': ['artisan'], 'headers': ['x-laravel-version']},
      'Symfony': {'cookies': ['symfony'], 'dirs': ['/app/config']},
      'Django': {'comments': ['Django'], 'files': ['manage.py']},
      'Express': {'files': ['package.json'], 'comments': ['Express']}
  }