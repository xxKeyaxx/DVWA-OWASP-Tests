# OWASP OTG-INPVAL-005 DVWA SQLi Prompt
**Use this prompt to convert an existing DVWA SQL-injection PoC script into a fully automated OTG-INPVAL-005 test & report generator.**

---

## Instructions for the AI
You are a senior penetration tester.  
I already have a working DVWA SQL-injection test script (DVWA SQLi PoC).  
Transform and extend that script so it:

1. **Fully covers the OWASP Testing Guide v4 test case OTG-INPVAL-005 (SQL Injection).**
   - Map every sub-test in OTG-INPVAL-005 to a concrete test step executed against DVWA (LOW / MEDIUM / HIGH security levels).  
   - Use the existing DVWA login & session-handling helpers already present in my PoC script.  
   - Add checks for:  
     - Error-based SQLi  
     - Boolean-based blind SQLi  
     - Time-based blind SQLi (MySQL `SLEEP()`)  
     - UNION-based data extraction  
     - Authentication bypass scenarios  
   - Prove detection by extracting one arbitrary table name and one arbitrary username/password pair (no destructive writes).  
   - Record request/response pairs for every payload including HTTP headers and body.  
   - Measure response times for time-based tests.

2. **Generate a machine-readable OWASP OTG-INPVAL-005 report bundle** containing:
   a. `executive_summary.md` – 150-word non-technical summary.  
   b. `test_evidence.json` – array of objects with keys:  
      ```json
      {
        "test_id": "",
        "security_level": "",
        "vector": "",
        "payload": "",
        "expected_result": "",
        "actual_result": "",
        "response_time_ms": 0,
        "screenshot_path": "",
        "status": ""
      }
      ```  
   c. `findings.md` – markdown table listing each finding with OWASP risk rating (Likelihood / Impact) and CVSS v3.1 vector.  
   d. `remediation.md` – one paragraph per finding with OWASP Cheat Sheet links.  
   e. `appendix_a_requests.md` – raw HTTP requests/responses in ```http blocks.  
   f. `appendix_b_evidence.zip` – PNG screenshots of DVWA output & sqlmap logs (auto-capture with headless browser or sqlmap `--screenshot`).

3. **Package the extended script** so that running:
   ```bash
   python3 dvwa_otg_inpval005.py --url http://dvwa.local --report_dir ./reports