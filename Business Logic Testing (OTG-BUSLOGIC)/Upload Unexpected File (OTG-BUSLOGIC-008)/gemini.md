# DVWA File Upload Vulnerability Testing and OWASP Report Generation

## Objective

This document outlines the process for testing the "Upload of Unexpected File Types" vulnerability (OWASP OTG-BUSLOGIC-008) on a locally hosted DVWA instance (via XAMPP) and generating an OWASP-compliant report.

## Target Environment

* **Application:** DVWA (Damn Vulnerable Web Application)
* **Hosting:** Locally via XAMPP
* **Vulnerability Focus:** File Upload (specifically, allowing unexpected file types)
* **Security Level:** Low (for initial testing and demonstration)

## Part 1: Python Script for Automated Testing

### Gemini Agent Prompt for Script Generation:

"**Please generate a Python script using the `requests` library to automate the testing of the file upload vulnerability in DVWA. The script should target the 'File Upload' section of DVWA, specifically at the 'low' security level. It needs to perform the following actions:**

1.  **Login to DVWA:** Use the default credentials (username: `admin`, password: `password`).
2.  **Navigate to File Upload Page:** Access the `/vulnerabilities/upload/` endpoint.
3.  **Attempt to Upload Unexpected File Types:** The script should try uploading several non-image file types (e.g., `.php`, `.exe`, `.html` containing a simple script, `.txt`) to the server.
    * For each upload attempt, include a legitimate `Content-Type` header (e.g., `application/octet-stream` or `text/plain` for the `.txt` file) to see if DVWA's server-side validation relies solely on file extension or on `Content-Type`.
    * Also, try to bypass client-side checks (if any) by directly sending the request with Burp Suite (manual step, but acknowledge its importance for a complete test).
4.  **Capture Responses:** For each upload attempt, capture the server's response (HTTP status code, response body) to determine if the upload was successful or blocked.
5.  **Log Results:** Print the results of each upload attempt to the console, indicating the file type, success/failure, and relevant server messages.
6.  **Include instructions for setting DVWA security level to 'low' and resetting the DVWA database.**

**Assumptions:**

* DVWA is hosted at `http://localhost/dvwa/`.
* The XAMPP Apache and MySQL services are running.
* The DVWA database is set up and accessible.

**Expected Output:**

The script should be a well-commented Python file ready for execution, providing clear output for each test case."

---

## Part 2: OWASP Report Generation

### Manual Steps for OWASP Report Preparation:

After running the Python script and observing the behavior, you'll manually generate the OWASP report. You can use a template or structure it as follows:

### Gemini Agent Prompt for OWASP Report Content:

"**Based on the successful execution of the Python script that tests the 'Upload of Unexpected File Types' (OTG-BUSLOGIC-008) vulnerability on DVWA (low security level), please provide the content for an OWASP-compliant penetration test report. The report should include the following sections, tailored to the specific findings of this file upload vulnerability:**

1.  **Executive Summary:** A concise overview of the finding, its impact, and overall risk.
2.  **Vulnerability Details:**
    * **Vulnerability Name:** Unrestricted File Upload (OTG-BUSLOGIC-008: Test Upload of Unexpected File Types)
    * **Affected Component/URL:** `http://localhost/dvwa/vulnerabilities/upload/`
    * **Description:** Explain what an unrestricted file upload vulnerability is and why it's a risk.
    * **Impact:** Describe the potential consequences of this vulnerability (e.g., remote code execution, denial of service, website defacement, sensitive data exposure).
    * **Proof of Concept (PoC) / Steps to Reproduce:**
        * Detailed steps for reproducing the vulnerability, including how to set DVWA to low security, login, and what files were attempted.
        * Include a screenshot (conceptual, as Gemini can't generate images) showing a successful upload of an unexpected file type (e.g., a PHP shell).
        * Mention the HTTP request and response for a successful exploit (e.g., uploading a `.php` file and then accessing it).
3.  **Risk Rating:** Assign a risk rating (e.g., High, Medium, Low) based on impact and likelihood, providing justification.
4.  **Recommendations:**
    * **Technical Mitigations:** Specific technical solutions (e.g., strict whitelist for file extensions, content-type validation, file renaming, anti-malware scanning, storing uploads outside the web root, `exec()` and `shell_exec()` hardening).
    * **General Best Practices:** Broader security advice for file upload functionalities.
5.  **Tools Used:** List the tools used (e.g., Python `requests` library, potentially Burp Suite for manual verification).
6.  **References:** Link to relevant OWASP documentation (e.g., OWASP Web Security Testing Guide - OTG-BUSLOGIC-008, OWASP Unrestricted File Upload).

**Considerations for Report Content:**

* Assume a successful upload of a `.php` file (acting as a simple web shell) to demonstrate the highest impact.
* Emphasize the importance of server-side validation over client-side validation.
* The report should be professional and actionable."

---

### How to Use This Prompt:

1.  **Save as `dvwa_file_upload_test.md`:** Copy the entire content above and save it as a Markdown file.
2.  **Execute the Python Script:** When you're ready, take the first Gemini prompt (for the Python script) and use it with a Gemini agent. Run the generated script against your local DVWA instance.
3.  **Gather Findings:** Observe the output of the Python script. Take note of which file types were successfully uploaded and any error messages. If you manually test with Burp Suite, record those observations as well.
4.  **Generate the OWASP Report Content:** Use the second Gemini prompt (for the OWASP report content) and provide the findings from your script. You may need to refine the Gemini's output slightly to perfectly match your specific test results and to add concrete screenshots if you performed a manual test.

This approach breaks down the task into manageable steps, leveraging Gemini's capabilities for both script generation and report content creation, while ensuring the final report adheres to OWASP guidelines.