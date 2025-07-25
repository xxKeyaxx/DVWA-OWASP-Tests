# Prompt for automating OTG-ERR-001 (Error Handling) testing against DVWA

> **Copy-paste this entire block into ChatGPT, Claude, or any LLM agent to generate a single-file Python 3 security-test script.**

---

You are a security-test automation expert.  
Build a single self-contained Python 3 script that:

1. Installs its own dependencies (`requests`, `beautifulsoup4`, `colorama`, `Jinja2`) via `pip` in a virtual-env if they are missing.  
2. Logs into a local DVWA instance (URL, username, password all configurable via CLI flags or env vars, defaults: `http://localhost/dvwa`, `admin` / `password`).  
3. Sets DVWA’s security level to the value given on the CLI (`--level low | medium | high | impossible`) or refuses to run if that cannot be done.  
4. Enumerates every page and form that accepts user input (login, sqli, upload, command injection, etc.) by spidering the authenticated session.  
5. For each parameter on each form/page:  
   a. Submits a canary payload designed to trigger a verbose error (examples below).  
   b. Captures the full HTTP request/response pair plus any stack-trace or SQL error text.  
   c. Uses simple heuristics to decide whether the response leaked sensitive info (stack trace, full file path, SQL query fragments, ODBC/JDBC messages, PHP errors, etc.).  
6. Generates an OWASP-aligned HTML report for OTG-ERR-001 (“Analysis of Error Codes”) that contains:  
   - Executive summary (total endpoints tested, total findings, risk rating).  
   - Detailed table for every finding: URL, parameter, payload, evidence snippet, CWE-209 (Information Exposure Through an Error Message) link, remediation advice.  
   - Reproducible curl commands for each issue.  
   - Chart (pie or bar) created with Chart.js CDN to visualise error type distribution.  
7. Saves the report to `dvwa-otg-err-001-<timestamp>.html` and also prints a short coloured CLI summary.  
8. Runs cleanly without user interaction (headless) and exits non-zero if any high-severity findings are detected.

### Canary payload list (rotate through them per parameter):
- `' or 1=1--`  
- `../../etc/passwd`  
- `<svg onload=alert(1)>`  
- `$(sleep 5)`  
- `AAAAA… × 10 000` (long string)  
- `{{7*7}}` (template injection hint)

### Extra requirements
- Use a single file, no external config files.  
- Follow PEP 8, add docstrings.  
- Do not use Selenium; rely only on `requests` + `BS4`.  
- If DVWA returns a custom 200 page that still contains an error message, the script must still flag it.  
- Provide a `--quiet` flag that suppresses all but the final report path.  
- Provide a `--dry-run` flag that prints the attack plan but does not send requests.

Start the script with a shebang and a comment block showing the exact CLI usage example.  
Deliver only the finished script, no explanations.