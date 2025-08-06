# DVWA-OWASP-Tests

This report summarizes the findings of a web application security assessment conducted on the Damn Vulnerable Web Application (DVWA). The tests were performed following the OWASP Testing Guide methodology to identify and exploit common web vulnerabilities.

## **Team Information**

* **Kevin Wijaya** \- 2540124993  
* **Muhammad Abdullah Faqih** \- 2501987330

## Summary

The assessment simulated an internal penetration test targeting a locally hosted DVWA instance. The primary objective was to evaluate the application's security by identifying and exploiting its intentionally designed vulnerabilities.

Multiple critical vulnerabilities were discovered and successfully exploited, including **SQL Injection, Command Injection, Cross-Site Scripting (XSS), and Insecure File Uploads**. These findings highlight common security weaknesses that can lead to full system compromise, including administrative control, data theft, and remote code execution.

**Key Recommendations:**

* Implement strict input validation and output encoding across the application.  
* Use parameterized queries to prevent SQL injection.  
* Harden the server configuration to disable dangerous functions and restrict file permissions.  
* Enforce strong access control and session management.

## **Scope of Testing**

A total of 87 tests were conducted based on the OWASP Testing Guide, covering the following areas:

* **Information Gathering (OTG-INFO)**: Reconnaissance, fingerprinting the web server and application, and identifying entry points.  
* **Configuration and Deployment Management (OTG-CONFIG)**: Reviewing server configuration, file extensions, and administrative interfaces.  
* **Identity Management (OTG-IDENT)**: Testing role definitions, user registration, and account enumeration.  
* **Authentication Testing (OTG-AUTHN)**: Assessing credential security, lockout mechanisms, and authentication bypass.  
* **Authorization Testing (OTG-AUTHZ)**: Evaluating directory traversal, privilege escalation, and insecure direct object references.  
* **Session Management Testing (OTG-SESS)**: Analyzing cookie attributes, session fixation, and CSRF protections.  
* **Input Validation Testing (OTG-INPVAL)**: Testing for vulnerabilities like XSS, SQL Injection, and Command Injection.  
* **Error Handling (OTG-ERR)**: Checking for information leakage through error messages and stack traces.  
* **Weak Cryptography (OTG-CRYPST)**: Assessing the use of SSL/TLS and unencrypted channels.  
* **Business Logic Testing (OTG-BUSLOGIC)**: Evaluating data validation, workflow integrity, and misuse defenses.  
* **Client-Side Testing (OTG-CLIENT)**: Testing for DOM-based XSS, JavaScript execution, and Clickjacking.

## **Conclusion**

The Damn Vulnerable Web Application (DVWA) successfully demonstrates a wide range of severe security vulnerabilities. While it is an educational tool, the flaws found are representative of real-world issues. Remediating these vulnerabilities requires a defense-in-depth approach, focusing on secure coding practices, robust server configuration, and strict access control.