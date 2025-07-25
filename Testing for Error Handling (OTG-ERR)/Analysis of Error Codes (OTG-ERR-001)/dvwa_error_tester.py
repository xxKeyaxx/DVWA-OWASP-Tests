#!/usr/bin/env python3
#
# Usage:
# python dvwa_error_tester.py --url http://localhost/dvwa --username admin --password password --level low
#
"""
OTG-ERR-001: Automated Error Handling Tester for DVWA.

This script automates the process of testing for information leakage through error
messages in the Damn Vulnerable Web Application (DVWA). It logs in, spiders the
application to find all forms, submits a series of canary payloads to each
input field, and analyzes the responses for signs of verbose error messages.

The script generates a detailed HTML report with findings, evidence, and
remediation advice, along with a summary on the command line.
"""

import argparse
import datetime
import os
import re
import subprocess
import sys
from urllib.parse import urljoin, urlparse

# --- Dependency Management ---

try:
    import requests
    from bs4 import BeautifulSoup
    from colorama import Fore, Style, init
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("One or more required libraries are not installed.")
    print("Attempting to install them now...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "beautifulsoup4", "colorama", "Jinja2"])
        print("Dependencies installed successfully. Please re-run the script.")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to install dependencies: {e}")
        print("Please install them manually: pip install requests beautifulsoup4 colorama Jinja2")
        sys.exit(1)

# Initialize colorama
init(autoreset=True)

# --- Canary Payloads ---
CANARY_PAYLOADS = [
    "' or 1=1--",
    "../../etc/passwd",
    "<svg onload=alert(1)>",
    "$(sleep 5)",
    "A" * 10000,
    "{{7*7}}",
]

# --- Error Patterns ---
ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*?MySQL", re.IGNORECASE),
    re.compile(r"Warning: mysql_.*", re.IGNORECASE),
    re.compile(r"Fatal error:.* on line \d+", re.IGNORECASE),
    re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"\[(ODBC|JDBC)\]", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB Provider for", re.IGNORECASE),
    re.compile(r"java\\.sql\\.SQLException", re.IGNORECASE),
    re.compile(r"stack trace", re.IGNORECASE),
    re.compile(r"in \/.+?\\.php on line \d+", re.IGNORECASE),
]

# --- HTML Report Template ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTG-ERR-001 Test Report for DVWA</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 2em; background-color: #f4f4f4; color: #333; }
        h1, h2 { color: #0056b3; }
        table { width: 100%; border-collapse: collapse; margin-top: 1em; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #0056b3; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .summary, .findings, .report-meta { background-color: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2em; }
        .curl-command { background-color: #eee; padding: 1em; border-radius: 4px; font-family: monospace; white-space: pre-wrap; word-wrap: break-word; }
        .evidence { background-color: #fdeaea; color: #c53030; padding: 1em; border-radius: 4px; font-family: monospace; white-space: pre-wrap; }
        .risk-high { color: #c53030; font-weight: bold; }
        .risk-medium { color: #d69e2e; font-weight: bold; }
        .risk-low { color: #38a169; font-weight: bold; }
        .chart-container { width: 50%; margin: auto; }
    </style>
</head>
<body>
    <h1>OTG-ERR-001: Information Exposure Through an Error Message</h1>
    <div class="report-meta">
        <p><strong>Test Target:</strong> {{ target_url }}</p>
        <p><strong>Report Generated:</strong> {{ timestamp }}</p>
        <p><strong>Security Level Tested:</strong> {{ security_level }}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Endpoints Tested:</strong> {{ total_endpoints }}</p>
        <p><strong>Total Findings:</strong> <span class="risk-high">{{ findings | length }}</span></p>
        <p><strong>Overall Risk:</strong> <span class="risk-high">High</span> (if findings > 0, else Low)</p>
        <div class="chart-container">
            <canvas id="errorChart"></canvas>
        </div>
    </div>

    <div class="findings">
        <h2>Detailed Findings</h2>
        {% if findings %}
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Payload</th>
                        <th>Evidence</th>
                        <th>Details</th>
                        <th>Reproduction</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in findings %}
                    <tr>
                        <td>{{ finding.url }}</td>
                        <td>{{ finding.param }}</td>
                        <td>{{ finding.payload }}</td>
                        <td><pre class="evidence">{{ finding.evidence }}</pre></td>
                        <td>
                            <p>Leaked sensitive information via error message.</p>
                            <p><a href="https://owasp.org/www-community/attacks/Full_Path_Disclosure" target="_blank">CWE-209: Information Exposure Through an Error Message</a></p>
                            <p><strong>Remediation:</strong> Configure the web server to display generic error messages and disable verbose error reporting.</p>
                        </td>
                        <td><pre class="curl-command">{{ finding.curl }}</pre></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% else %}
            <p class="risk-low">No verbose error messages were detected.</p>
        {% endif %}
    </div>

    <script>
        const ctx = document.getElementById('errorChart').getContext('2d');
        const errorChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Findings', 'Clean'],
                datasets: [{
                    label: 'Test Results',
                    data: [{{ findings | length }}, {{ total_endpoints - (findings | length) }}],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                    ],
                    borderColor: [
                        'rgba(255, 99, 132, 1)',
                        'rgba(75, 192, 192, 1)',
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'Test Outcome Distribution'
                    }
                }
            }
        });
    </script>
</body>
</html>
"""

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="OTG-ERR-001 Tester for DVWA")
    parser.add_argument("--url", default=os.environ.get("DVWA_URL", "http://localhost/dvwa"), help="URL of the DVWA instance.")
    parser.add_argument("--username", default=os.environ.get("DVWA_USER", "admin"), help="DVWA username.")
    parser.add_argument("--password", default=os.environ.get("DVWA_PASS", "password"), help="DVWA password.")
    parser.add_argument("--level", required=True, choices=["low", "medium", "high", "impossible"], help="DVWA security level to test.")
    parser.add_argument("--quiet", action="store_true", help="Suppress all output except the final report path.")
    parser.add_argument("--dry-run", action="store_true", help="Print the attack plan without sending requests.")
    return parser.parse_args()

def log_message(message, quiet=False):
    """Prints a message unless in quiet mode."""
    if not quiet:
        print(message)

def login_to_dvwa(session, url, username, password, quiet=False):
    """Logs into DVWA and returns the session."""
    log_message(f"{Fore.YELLOW}[*] Attempting to log in to {url}...", quiet)
    login_url = urljoin(url, "login.php")
    
    # Get login page to extract user_token
    try:
        response = session.get(login_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Failed to connect to DVWA at {login_url}: {e}")
        sys.exit(1)

    soup = BeautifulSoup(response.text, "html.parser")
    user_token = soup.find("input", {"name": "user_token"})
    if not user_token:
        print(f"{Fore.RED}[!] Could not find user_token on login page. Is this a valid DVWA URL?")
        sys.exit(1)
    user_token = user_token["value"]

    payload = {
        "username": username,
        "password": password,
        "user_token": user_token,
        "Login": "Login",
    }
    
    response = session.post(login_url, data=payload, allow_redirects=True)
    
    if "welcome.php" in response.url or "index.php" in response.url:
        log_message(f"{Fore.GREEN}[+] Login successful.", quiet)
        return True
    else:
        log_message(f"{Fore.RED}[-] Login failed. Check credentials.", quiet)
        return False

def set_dvwa_security(session, url, level, quiet=False):
    """Sets the DVWA security level."""
    log_message(f"{Fore.YELLOW}[*] Setting security level to '{level}'...", quiet)
    security_url = urljoin(url, "security.php")
    
    try:
        response = session.get(security_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Failed to access security page: {e}")
        return False

    soup = BeautifulSoup(response.text, "html.parser")
    user_token = soup.find("input", {"name": "user_token"})
    if not user_token:
        print(f"{Fore.RED}[!] Could not find user_token on security page.")
        return False
    user_token = user_token["value"]

    payload = {
        "security": level,
        "seclev_submit": "Submit",
        "user_token": user_token,
    }
    
    response = session.post(security_url, data=payload)
    
    if f"Security level set to {level}" in response.text:
        log_message(f"{Fore.GREEN}[+] Security level successfully set to '{level}'.", quiet)
        return True
    else:
        log_message(f"{Fore.RED}[-] Failed to set security level.", quiet)
        return False

def spider_dvwa(session, base_url, quiet=False):
    """Spiders the DVWA application to find all unique forms."""
    log_message(f"{Fore.YELLOW}[*] Spidering the application to find forms...", quiet)
    
    links_to_visit = {urljoin(base_url, "index.php")}
    visited_links = set()
    forms_found = []

    while links_to_visit:
        current_url = links_to_visit.pop()
        if current_url in visited_links or not current_url.startswith(base_url):
            continue

        try:
            response = session.get(current_url)
            visited_links.add(current_url)
            log_message(f"  -> Visiting: {current_url}", quiet)
        except requests.exceptions.RequestException:
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        
        # Find new links to visit
        for link in soup.find_all("a", href=True):
            href = urljoin(base_url, link["href"])
            if href.startswith(base_url) and "#" not in href and "logout" not in href:
                links_to_visit.add(href)

        # Find forms on the page
        for form in soup.find_all("form"):
            action = urljoin(current_url, form.get("action", current_url))
            method = form.get("method", "get").lower()
            
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(name)
            
            if inputs:
                form_details = {"action": action, "method": method, "params": set(inputs)}
                if form_details not in forms_found:
                    forms_found.append(form_details)
                    log_message(f"    {Fore.CYAN}[+] Found form on {current_url} with params: {form_details['params']}", quiet)

    log_message(f"{Fore.GREEN}[+] Spidering complete. Found {len(forms_found)} unique forms.", quiet)
    return forms_found

def test_form(session, form_details, quiet=False):
    """Tests a single form with all canary payloads."""
    findings = []
    action = form_details["action"]
    method = form_details["method"]
    params = form_details["params"]

    log_message(f"{Fore.YELLOW}[*] Testing form at {action}...", quiet)

    for param in params:
        for payload in CANARY_PAYLOADS:
            data = {p: "test" for p in params}
            data[param] = payload
            
            # Ensure user_token is included if present on the form
            try:
                # We need to re-fetch the page to get a fresh token for each request
                page_res = session.get(action)
                soup = BeautifulSoup(page_res.text, 'html.parser')
                token_input = soup.find('input', {'name': 'user_token'})
                if token_input:
                    data['user_token'] = token_input['value']
            except requests.exceptions.RequestException:
                pass # Continue even if fetching the token fails

            try:
                if method == "post":
                    response = session.post(action, data=data)
                else:
                    response = session.get(action, params=data)
            except requests.exceptions.RequestException as e:
                log_message(f"    {Fore.RED}[!] Request failed for param {param}: {e}", quiet)
                continue

            for pattern in ERROR_PATTERNS:
                match = pattern.search(response.text)
                if match:
                    evidence = match.group(0)
                    log_message(f"  {Fore.RED}[!] VULNERABILITY FOUND!", quiet)
                    log_message(f"    - URL: {action}", quiet)
                    log_message(f"    - Parameter: {param}", quiet)
                    log_message(f"    - Payload: {payload}", quiet)
                    log_message(f"    - Evidence: {evidence}", quiet)
                    
                    # Generate curl command
                    if method == 'post':
                        curl_data = " ".join([f"--data-urlencode '{k}={v}'" for k, v in data.items()])
                        curl_command = f"curl -X POST '{action}' {curl_data} -b 'security=low; PHPSESSID={session.cookies.get('PHPSESSID')}'"
                    else:
                        query_string = '&'.join([f"{k}={v}" for k,v in data.items()])
                        full_url = f"{action}?{query_string}"
                        curl_command = f"curl -X GET '{full_url}' -b 'security=low; PHPSESSID={session.cookies.get('PHPSESSID')}'"


                    findings.append({
                        "url": action,
                        "param": param,
                        "payload": payload,
                        "evidence": evidence,
                        "curl": curl_command,
                    })
                    break # Move to next payload once a finding is registered for this one
    return findings

def generate_html_report(template_str, data, quiet=False):
    """Generates an HTML report from the findings."""
    log_message(f"{Fore.YELLOW}[*] Generating HTML report...", quiet)
    from jinja2 import Environment, BaseLoader
    env = Environment(loader=BaseLoader())
    template = env.from_string(template_str)
    
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"dvwa-otg-err-001-{timestamp}.html"
    
    rendered_html = template.render(
        findings=data["findings"],
        total_endpoints=data["total_endpoints"],
        target_url=data["target_url"],
        security_level=data["security_level"],
        timestamp=timestamp
    )
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(rendered_html)
        
    log_message(f"{Fore.GREEN}[+] Report saved to: {os.path.abspath(filename)}", quiet=False) # Always print this
    return os.path.abspath(filename)

def print_cli_summary(findings, quiet=False):
    """Prints a colored summary to the console."""
    if quiet:
        return

    print("\n" + "="*50)
    print(f"{Style.BRIGHT}CLI Summary{Style.RESET_ALL}")
    print("="*50)
    if not findings:
        print(f"{Fore.GREEN}No verbose error vulnerabilities found.")
    else:
        print(f"{Fore.RED}{Style.BRIGHT}Found {len(findings)} vulnerabilities!{Style.RESET_ALL}")
        for finding in findings:
            print(f"  - {Fore.CYAN}URL:{Style.RESET_ALL} {finding['url']}")
            print(f"    {Fore.CYAN}Parameter:{Style.RESET_ALL} {finding['param']}")
            print(f"    {Fore.RED}Evidence:{Style.RESET_ALL} {finding['evidence']}")
    print("="*50 + "\n")


def main():
    """Main function to run the scanner."""
    args = parse_arguments()

    # Ensure the URL has a trailing slash for correct urljoin behavior
    if not args.url.endswith('/'):
        args.url += '/'

    if not args.quiet:
        print(Style.BRIGHT + "--- DVWA Error Handling Scanner ---" + Style.RESET_ALL)

    if args.dry_run:
        log_message(f"{Fore.YELLOW}[DRY RUN] Configuration:", args.quiet)
        log_message(f"  - URL: {args.url}", args.quiet)
        log_message(f"  - Level: {args.level}", args.quiet)
        log_message(f"{Fore.YELLOW}[DRY RUN] Plan:", args.quiet)
        log_message("  1. Log in to DVWA.", args.quiet)
        log_message("  2. Set security level.", args.quiet)
        log_message("  3. Spider application to find all forms.", args.quiet)
        log_message("  4. For each form parameter, submit canary payloads.", args.quiet)
        log_message("  5. Analyze responses for error messages.", args.quiet)
        log_message("  6. Generate HTML report.", args.quiet)
        sys.exit(0)

    session = requests.Session()
    session.headers.update({"User-Agent": "DVWA-Security-Scanner/1.0"})

    if not login_to_dvwa(session, args.url, args.username, args.password, args.quiet):
        sys.exit(1)

    if not set_dvwa_security(session, args.url, args.level, args.quiet):
        print(f"{Fore.RED}[!] Refusing to run because security level could not be set.")
        sys.exit(1)

    forms = spider_dvwa(session, args.url, args.quiet)
    if not forms:
        log_message(f"{Fore.YELLOW}[*] No forms found to test.", args.quiet)
        sys.exit(0)

    all_findings = []
    total_params_tested = 0
    for form in forms:
        total_params_tested += len(form["params"])
        findings = test_form(session, form, args.quiet)
        all_findings.extend(findings)

    report_data = {
        "findings": all_findings,
        "total_endpoints": total_params_tested,
        "target_url": args.url,
        "security_level": args.level,
    }

    generate_html_report(HTML_TEMPLATE, report_data, args.quiet)
    print_cli_summary(all_findings, args.quiet)

    if all_findings:
        sys.exit(1) # Exit with non-zero code if findings are detected
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
