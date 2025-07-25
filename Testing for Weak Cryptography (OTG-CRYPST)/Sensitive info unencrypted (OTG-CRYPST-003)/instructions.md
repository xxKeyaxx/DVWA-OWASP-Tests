# **Prompt for AI Coding Agent: Automated DOM XSS Test and OWASP Report Generation**

## **1\. Objective**

Your primary task is to create a Python script that automates the testing for DOM-based Cross-Site Scripting (XSS) vulnerabilities on the Damn Vulnerable Web Application (DVWA). After conducting the test, the script must generate a comprehensive, well-structured, and professionally designed HTML report based on the findings, following OWASP reporting standards.

## **2\. Target Environment**

* **Application:** Damn Vulnerable Web Application (DVWA)  
* **Hosting:** Localhost via XAMPP  
* **URL:** http://localhost/dvwa/  
* **Specific Target Page:** "XSS (DOM)" page within DVWA.  
* **DVWA Security Level:** The script should be designed to work on the 'low' security setting, but please include comments on how it might be adapted for 'medium' or 'high' levels.  
* **Credentials:**  
  * **Username:** admin  
  * **Password:** password

## **3\. Core Requirements for the Python Script**

You must use **Python 3** with the **Selenium** library for web browser automation.

### **Task Breakdown:**

1. **Initialization:**  
   * The script must initialize a Selenium WebDriver (e.g., for Chrome or Firefox).  
   * It should be configured to handle any necessary driver path settings.  
2. **Login and Navigation:**  
   * Automate the process of navigating to the DVWA login page (http://localhost/dvwa/login.php).  
   * Enter the credentials (admin/password) and submit the form to log in.  
   * After logging in, navigate directly to the DOM-based XSS test page: http://localhost/dvwa/vulnerabilities/xss\_d/.  
3. **Vulnerability Testing (OTG-CLIENT-001):**  
   * The core of the test involves manipulating the URL to inject a payload. The DVWA DOM XSS page uses the URL fragment (\#) to dynamically write to the page's DOM.  
   * The script should identify the default parameter in the URL's query string.  
   * Construct a series of test payloads. Include at least the following:  
     * A basic script alert: \<script\>alert('XSS-SUCCESS-1')\</script\>  
     * An image-based payload: \<img src=x onerror=alert('XSS-SUCCESS-2')\>  
     * A more complex payload that might bypass simple filters: \<iframe src="javascript:alert('XSS-SUCCESS-3');"\>  
   * For each payload, the script must:  
     * Modify the URL to include the payload. For the DVWA DOM XSS page, the URL should look like: http://localhost/dvwa/vulnerabilities/xss\_d/\#\<payload\_here\> (Note: The payload is passed in the URL fragment, not a standard query parameter).  
     * Load the modified URL.  
     * Use Selenium's WebDriverWait to check for the appearance of a JavaScript alert box.  
     * Record whether the alert was successfully triggered for each payload. This confirms the vulnerability.  
4. **Data Collection for Report:**  
   * Log all actions: navigation steps, payloads tested, and outcomes (success/failure).  
   * Capture screenshots of the successful XSS payload executions (i.e., when the alert box is visible). Save these images to a designated results folder.  
   * Record the exact URL and payload that resulted in a successful exploit.

## **4\. Requirements for the HTML Report**

The script's final output must be a single, self-contained HTML file named DVWA\_DOM\_XSS\_Report.html. This report should be professional, well-designed, and easy to read.

### **Report Structure:**

* **Header:**  
  * Title: "OWASP Web Application Security Test Report"  
  * Subtitle: "OTG-CLIENT-001: DOM-Based Cross-Site Scripting on DVWA"  
  * Report Date, Target URL, and Tester Name (use a placeholder like "Automated Test Agent").  
* **Executive Summary:**  
  * **Vulnerability:** DOM-Based Cross-Site Scripting (XSS)  
  * **Severity:** High  
  * **Status:** **Vulnerable** (or **Not Vulnerable** if no payloads succeed).  
  * A brief, non-technical paragraph explaining that the application was found to be vulnerable to DOM XSS, allowing attackers to execute arbitrary scripts in the user's browser.  
* **Test Methodology:**  
  * A short description of the automated test process: logging in, navigating to the target page, and injecting payloads via the URL fragment.  
  * Mention the tools used: Python, Selenium.  
* **Findings & Evidence:**  
  * This section should be dynamically generated based on the test results.  
  * For each **successful** payload:  
    * Create a subsection for the finding.  
    * **Payload:** Display the exact payload string used (e.g., \<script\>alert('XSS-SUCCESS-1')\</script\>).  
    * **Proof of Concept URL:** Display the full URL that triggered the vulnerability.  
    * **Evidence:** Embed the screenshot captured during the successful test. The image should be displayed directly in the report.  
* **Vulnerability Description (OWASP Style):**  
  * Include a detailed explanation of what DOM-based XSS is. Explain that the vulnerability occurs when client-side scripts write user-provided data directly to the Document Object Model (DOM) without proper sanitization.  
* **Impact:**  
  * Describe the potential business and technical impacts, such as session hijacking, data theft, phishing attacks, and website defacement.  
* **Recommendations & Remediation:**  
  * Provide clear and actionable steps to fix the vulnerability.  
  * **Primary Recommendation:** Avoid allowing data to be dynamically added to the DOM.  
  * **If unavoidable:** Use safe JavaScript APIs (e.g., textContent instead of innerHTML) to handle data.  
  * Implement context-sensitive encoding and sanitization on the client-side using a trusted library like DOMPurify before writing data to the DOM.  
  * Advise on implementing a Content Security Policy (CSP) as a defense-in-depth measure.

### **HTML Design & Styling:**

* Use inline CSS or a \<style\> block to ensure the report is a single file.  
* Use a clean, professional layout (e.g., a two-column layout for some sections is acceptable).  
* Use colors to highlight severity (e.g., red for "High" severity).  
* Ensure the report is responsive and readable on different screen sizes.  
* Code snippets (payloads, URLs) should be in a monospace font and visually distinct.

Please proceed with generating the complete Python script that performs these actions and produces the final HTML report.