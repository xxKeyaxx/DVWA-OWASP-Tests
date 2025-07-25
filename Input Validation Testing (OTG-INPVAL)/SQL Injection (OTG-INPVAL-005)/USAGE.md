# DVWA OTG-INPVAL-005 SQL Injection Testing Tool

## Overview
This tool performs comprehensive SQL injection testing against DVWA (Damn Vulnerable Web Application) according to OWASP Testing Guide v4 OTG-INPVAL-005. It tests all major SQL injection vectors across LOW, MEDIUM, and HIGH security levels.

## Installation

!!! Add rockyou.txt to this folder first !!!
!!! rockyou.txt link: https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt !!!

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure DVWA is running and accessible

## Usage

### Basic Usage
```bash
python dvwa_otg_inpval005.py --url http://localhost/dvwa --report_dir ./reports
```

### Advanced Usage
```bash
python dvwa_otg_inpval005.py \
  --url http://localhost/DVWA \
  --report_dir ./otg_reports \
  --username admin \
  --password password
```

### Command Line Arguments
- `--url`: DVWA base URL (required)
- `--report_dir`: Directory to save reports (default: ./reports)
- `--username`: DVWA username (default: admin)
- `--password`: DVWA password (default: password)

## Test Coverage

The tool tests the following SQL injection vectors:

1. **Error-based SQLi** - Tests for SQL error messages
2. **Boolean-based blind SQLi** - Tests for true/false conditions
3. **Time-based blind SQLi** - Tests for MySQL SLEEP() delays
4. **UNION-based SQLi** - Tests for data extraction via UNION
5. **Authentication bypass** - Tests for login bypass scenarios

## Report Generation

The tool generates a complete OWASP-compliant report bundle:

### 1. Executive Summary (`executive_summary.md`)
- 150-word non-technical summary
- Vulnerability overview
- Risk assessment

### 2. Test Evidence (`test_evidence.json`)
- Machine-readable test results
- Complete payload details
- Response times and status

### 3. Findings (`findings.md`)
- Markdown table of all findings
- OWASP risk ratings (Likelihood/Impact)
- CVSS v3.1 vectors

### 4. Remediation (`remediation.md`)
- Specific remediation steps
- OWASP Cheat Sheet links
- Best practices

### 5. Appendix A (`appendix_a_requests.md`)
- Raw HTTP requests/responses
- Complete test evidence
- Headers and body content

### 6. Appendix B (`appendix_b_evidence.zip`)
- Screenshots (placeholder)
- Evidence collection

## Example Output Structure

```
reports/
├── executive_summary.md
├── test_evidence.json
├── findings.md
├── remediation.md
├── appendix_a_requests.md
└── appendix_b_evidence.zip
```

## Sample Test Evidence JSON Structure

```json
[
  {
    "test_id": "ERROR_LOW_1",
    "security_level": "low",
    "vector": "error_based_sqli",
    "payload": "1' OR 1=1",
    "expected_result": "SQL error or data extraction",
    "actual_result": "SQL error detected",
    "response_time_ms": 45.23,
    "screenshot_path": "",
    "status": "vulnerable"
  }
]
```

## Security Considerations

- **Non-destructive**: Tests only read data, no writes/deletes
- **Safe payloads**: Uses safe SQL injection payloads
- **Rate limiting**: Includes delays between tests
- **Session management**: Proper DVWA session handling

## Troubleshooting

### Common Issues

1. **Login Failed**
   - Check DVWA credentials
   - Verify CSRF token handling
   - Ensure DVWA security is properly configured

2. **Connection Errors**
   - Verify DVWA URL is correct
   - Check network connectivity
   - Ensure DVWA is running

3. **Permission Errors**
   - Ensure write permissions for report directory
   - Check file system access

### Debug Mode
Add debug logging by modifying the script to include:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## OWASP Compliance

This tool fully complies with:
- OWASP Testing Guide v4 OTG-INPVAL-005
- OWASP SQL Injection Prevention Cheat Sheet
- OWASP Risk Rating Methodology
- CVSS v3.1 scoring

## License

This tool is provided for educational and authorized testing purposes only.