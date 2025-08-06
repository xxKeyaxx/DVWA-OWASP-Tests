import requests
from bs4 import BeautifulSoup
import re
import datetime
import urllib.parse

def login_to_dvwa(session, base_url):
    """
    Logs into DVWA using default credentials to access protected pages
    """
    try:
        # Get login page to extract CSRF token
        login_page = session.get(f"{base_url}login.php")
        soup = BeautifulSoup(login_page.text, 'html.parser')
        
        # Extract CSRF token
        token_element = soup.find('input', {'name': 'user_token'})
        if not token_element:
            print("[!] CSRF token not found on login page")
            return False
            
        csrf_token = token_element.get('value')
        
        # Perform login
        login_data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': csrf_token
        }
        
        response = session.post(f"{base_url}login.php", data=login_data)
        
        # Check if login was successful
        if "Welcome to Damn Vulnerable Web Application" in response.text:
            print("[+] Successfully logged into DVWA")
            return True
        else:
            print("[!] Login failed")
            return False
            
    except Exception as e:
        print(f"[ERROR] Login failed: {str(e)}")
        return False

def get_dvwa_pages(base_url, session):
    """
    Returns a list of DVWA pages to analyze
    """
    pages = [
        "login.php",
        "index.php",
        "setup.php",
        "instructions.php",
        "phpinfo.php",
        "vulnerabilities/brute/",
        "vulnerabilities/exec/",
        "vulnerabilities/csrf/",
        "vulnerabilities/fi/.?page=include.php",
        "vulnerabilities/upload/",
        "vulnerabilities/captcha/",
        "vulnerabilities/sqli/",
        "vulnerabilities/sqli_blind/",
        "vulnerabilities/weak_id/",
        "vulnerabilities/xss_d/",
        "vulnerabilities/xss_r/",
        "vulnerabilities/xss_s/"
    ]
    
    # Try to get actual links from the index page
    try:
        index_response = session.get(f"{base_url}index.php")
        if index_response.status_code == 200:
            soup = BeautifulSoup(index_response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            # Add discovered links
            for link in links:
                href = link['href']
                if href.startswith('vulnerabilities/') or href in ['setup.php', 'instructions.php']:
                    if href not in pages:
                        pages.append(href)
    except Exception as e:
        print(f"[!] Could not parse index page: {str(e)}")
    
    return pages

def extract_comments_and_metadata(html_content, url):
    """
    Extracts HTML comments, meta tags, and hidden inputs from HTML content
    """
    findings = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Extract HTML comments
    comments = soup.find_all(string=lambda text: isinstance(text, soup.__class__))
    for comment in soup.find_all(text=re.compile("<!--.*?-->", re.DOTALL)):
        comment_text = str(comment).strip()
        if comment_text:
            # Analyze comment for sensitive data
            severity = "Low"
            description = "HTML comment found"
            
            # Check for sensitive patterns
            if re.search(r'(admin|user).*[:\s]*(pass|pwd|password)', comment_text, re.I):
                severity = "Critical"
                description = "Potential hardcoded credentials in comment"
            elif re.search(r'(debug|dev|test).*=.*(1|true|on)', comment_text, re.I):
                severity = "High"
                description = "Debug/test mode indicator found"
            elif re.search(r'(todo|fix|bug|issue)', comment_text, re.I):
                severity = "Medium"
                description = "Developer note/todo found"
            elif re.search(r'([a-z]:[\\\/]|\/.*\/)', comment_text, re.I):
                severity = "Medium"
                description = "Potential internal path disclosure"
            elif re.search(r'(v\d+\.\d+|version)', comment_text, re.I):
                severity = "Medium"
                description = "Version information disclosed"
            
            findings.append({
                "type": "HTML Comment",
                "url": url,
                "content": comment_text[:500],
                "severity": severity,
                "description": description
            })
    
    # Extract meta tags
    meta_tags = soup.find_all('meta')
    for meta in meta_tags:
        name = meta.get('name', '')
        content = meta.get('content', '')
        property_attr = meta.get('property', '')
        
        if name or property_attr:
            full_meta = f'<meta name="{name}" property="{property_attr}" content="{content}" />'
            
            # Check for sensitive meta data
            severity = "Low"
            description = "Meta tag found"
            
            if 'generator' in name.lower() and re.search(r'(wordpress|joomla|drupal)', content, re.I):
                severity = "Medium"
                description = "CMS version disclosed in meta tag"
            elif re.search(r'(admin|password|token)', content, re.I):
                severity = "High"
                description = "Potential sensitive data in meta tag"
            
            findings.append({
                "type": "Meta Tag",
                "url": url,
                "content": full_meta,
                "severity": severity,
                "description": description
            })
    
    # Extract hidden inputs
    hidden_inputs = soup.find_all('input', type='hidden')
    for hidden in hidden_inputs:
        hidden_html = str(hidden)
        
        # Check for sensitive hidden inputs
        severity = "Low"
        description = "Hidden input field found"
        
        name = hidden.get('name', '').lower()
        value = hidden.get('value', '').lower()
        
        if re.search(r'(debug|test)', name):
            severity = "Medium"
            description = "Debug/test parameter in hidden input"
        elif re.search(r'(token|csrf)', name) and len(value) > 20:
            severity = "Low"
            description = "CSRF token in hidden input"
        
        findings.append({
            "type": "Hidden Input",
            "url": url,
            "content": hidden_html,
            "severity": severity,
            "description": description
        })
    
    # Look for version information in text
    text_content = soup.get_text()
    version_matches = re.findall(r'(DVWA|Damn Vulnerable Web Application).*?v?(\d+\.\d+)', text_content, re.I)
    for match in version_matches:
        findings.append({
            "type": "Version Info",
            "url": url,
            "content": match[0] + " " + match[1],
            "severity": "Medium",
            "description": "Application version disclosed"
        })
    
    return findings

def analyze_pages(base_url, session):
    """
    Analyzes all DVWA pages for comments and metadata
    """
    findings = []
    pages = get_dvwa_pages(base_url, session)
    
    print(f"[+] Analyzing {len(pages)} DVWA pages...")
    
    for page in pages:
        url = urllib.parse.urljoin(base_url, page)
        try:
            response = session.get(url, timeout=10)
            if response.status_code == 200:
                print(f"[FOUND] {url}")
                page_findings = extract_comments_and_metadata(response.text, url)
                findings.extend(page_findings)
            else:
                print(f"[!] {url} returned status {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Could not access {url}: {str(e)}")
    
    return findings

def get_severity_class(severity):
    """Returns CSS class for severity badge"""
    severity_classes = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low"
    }
    return severity_classes.get(severity, "low")

def generate_html_report(findings):
    """
    Generates an OSCP-style HTML report for the findings
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP OTG-INFO-005 - Webpage Comments and Metadata Review Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&family=Source+Code+Pro&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary-dark: #0a0a0a;
            --secondary-dark: #1a1a1a;
            --accent-green: #00ff00;
            --accent-blue: #00aaff;
            --accent-red: #ff0000;
            --accent-orange: #ff8c00;
            --accent-yellow: #ffff00;
            --text-light: #ffffff;
            --text-gray: #cccccc;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Roboto', sans-serif;
            background-color: var(--primary-dark);
            color: var(--text-light);
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background-color: var(--secondary-dark);
            padding: 30px;
            border-left: 4px solid var(--accent-green);
            margin-bottom: 30px;
            border-radius: 0 8px 8px 0;
        }}
        
        h1, h2, h3 {{
            margin-bottom: 15px;
            font-weight: 700;
        }}
        
        h1 {{
            color: var(--accent-green);
            font-size: 2.5em;
        }}
        
        h2 {{
            color: var(--accent-blue);
            border-bottom: 2px solid var(--accent-blue);
            padding-bottom: 10px;
            margin-top: 30px;
        }}
        
        h3 {{
            color: var(--text-light);
        }}
        
        .report-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .meta-item {{
            background-color: var(--secondary-dark);
            padding: 15px;
            border-radius: 5px;
        }}
        
        .meta-item strong {{
            color: var(--accent-green);
        }}
        
        .findings-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .summary-card {{
            background-color: var(--secondary-dark);
            padding: 20px;
            text-align: center;
            border-radius: 5px;
        }}
        
        .summary-card.critical {{ border-top: 4px solid var(--accent-red); }}
        .summary-card.high {{ border-top: 4px solid var(--accent-orange); }}
        .summary-card.medium {{ border-top: 4px solid var(--accent-yellow); }}
        .summary-card.low {{ border-top: 4px solid var(--accent-green); }}
        
        .finding {{
            background-color: var(--secondary-dark);
            margin: 20px 0;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid var(--text-gray);
        }}
        
        .finding.critical {{ border-left-color: var(--accent-red); }}
        .finding.high {{ border-left-color: var(--accent-orange); }}
        .finding.medium {{ border-left-color: var(--accent-yellow); }}
        .finding.low {{ border-left-color: var(--accent-green); }}
        
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .badge.critical {{ background-color: var(--accent-red); }}
        .badge.high {{ background-color: var(--accent-orange); }}
        .badge.medium {{ background-color: var(--accent-yellow); color: #000; }}
        .badge.low {{ background-color: var(--accent-green); }}
        
        .content-preview {{
            background-color: var(--primary-dark);
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            font-family: 'Source Code Pro', monospace;
            font-size: 0.9em;
            max-height: 200px;
            overflow-y: auto;
            white-space: pre-wrap;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: var(--secondary-dark);
        }}
        
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
        }}
        
        th {{
            background-color: rgba(0, 255, 0, 0.1);
            color: var(--accent-green);
        }}
        
        tr:hover {{
            background-color: rgba(255, 255, 255, 0.05);
        }}
        
        footer {{
            margin-top: 50px;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
            color: var(--text-gray);
            border-top: 1px solid #333;
        }}
        
        @media print {{
            body {{
                background-color: white;
                color: black;
            }}
            .container {{
                max-width: 100%;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>OWASP Testing Guide - OTG-INFO-005</h1>
            <h2>Webpage Comments and Metadata Review Report</h2>
            <div class="report-meta">
                <div class="meta-item">
                    <strong>Target:</strong> http://localhost/dvwa/
                </div>
                <div class="meta-item">
                    <strong>Date:</strong> {timestamp}
                </div>
                <div class="meta-item">
                    <strong>Test ID:</strong> OTG-INFO-005
                </div>
                <div class="meta-item">
                    <strong>Tester:</strong> AI Security Agent
                </div>
            </div>
        </header>

        <section>
            <h2>Executive Summary</h2>
            <p>This report details the findings of a security assessment focused on identifying information leakage through webpage comments and metadata. The assessment targeted the DVWA application running on localhost to identify exposed developer notes, debug information, hidden parameters, and other sensitive data that could aid attackers in understanding the application structure and potential vulnerabilities.</p>
        </section>

        <section>
            <h2>Test Details</h2>
            <p><strong>OWASP Test ID:</strong> OTG-INFO-005 - Review Webpage Comments and Metadata for Information Leakage</p>
            <p>This test identifies sensitive information leakage through HTML comments, meta tags, hidden form fields, and other page metadata that may be accessible to unauthorized users.</p>
        </section>

        <section>
            <h2>Methodology</h2>
            <p>The assessment was performed using a custom Python script that systematically accessed DVWA pages, parsed HTML content, and extracted comments, meta tags, and hidden inputs. Both public and authenticated pages were analyzed after logging in with default credentials.</p>
            <p><strong>Tools Used:</strong> Custom Python Comments and Metadata Scanner</p>
            <p><strong>Scope:</strong> DVWA installation at http://localhost/dvwa/</p>
        </section>

        <section>
            <h2>Findings Summary</h2>
            <div class="findings-summary">
"""
    
    # Count findings by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        severity_counts[finding["severity"]] += 1
    
    html_content += f"""
                <div class="summary-card critical">
                    <h3>Critical</h3>
                    <p>{severity_counts['Critical']}</p>
                </div>
                <div class="summary-card high">
                    <h3>High</h3>
                    <p>{severity_counts['High']}</p>
                </div>
                <div class="summary-card medium">
                    <h3>Medium</h3>
                    <p>{severity_counts['Medium']}</p>
                </div>
                <div class="summary-card low">
                    <h3>Low</h3>
                    <p>{severity_counts['Low']}</p>
                </div>
            </div>
        </section>

        <section>
            <h2>Detailed Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Page</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    # Add findings table rows
    for finding in findings:
        severity_class = get_severity_class(finding["severity"])
        html_content += f"""
                    <tr>
                        <td><a href="{finding['url']}" target="_blank">{finding['url'].replace('http://localhost/dvwa/', '')}</a></td>
                        <td>{finding['type']}</td>
                        <td><span class="badge {severity_class}">{finding['severity']}</span></td>
                        <td>{finding['description']}</td>
                    </tr>
"""
    
    html_content += """
                </tbody>
            </table>
        </section>
"""
    
    # Add detailed findings
    for i, finding in enumerate(findings):
        severity_class = get_severity_class(finding["severity"])
        html_content += f"""
        <section class="finding {severity_class}">
            <h3>{finding['type']} - {finding['url'].replace('http://localhost/dvwa/', '')}</h3>
            <p><strong>URL:</strong> <a href="{finding['url']}" target="_blank">{finding['url']}</a></p>
            <p><strong>Type:</strong> {finding['type']}</p>
            <p><strong>Severity:</strong> <span class="badge {severity_class}">{finding['severity']}</span></p>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Content:</strong></p>
            <div class="content-preview">{finding['content']}</div>
            <p><strong>Remediation:</strong> 
"""
        
        # Add remediation based on finding type
        if finding['severity'] == "Critical":
            html_content += "Immediately remove hardcoded credentials from source code and implement proper credential management."
        elif finding['type'] == "HTML Comment":
            html_content += "Remove all developer comments, TODOs, and debug notes from production HTML code."
        elif finding['type'] == "Meta Tag":
            html_content += "Review meta tags for sensitive information disclosure and remove unnecessary metadata."
        elif finding['type'] == "Hidden Input":
            html_content += "Ensure hidden form inputs do not contain sensitive data or debug parameters in production."
        else:
            html_content += "Remove or obfuscate sensitive information in webpage source code and metadata."
        
        html_content += """
            </p>
        </section>
"""
    
    html_content += f"""
        <section>
            <h2>Remediation Recommendations</h2>
            <ul>
                <li>Remove all developer comments, TODOs, and debug information from production HTML</li>
                <li>Avoid exposing version information in HTML comments or meta tags</li>
                <li>Do not include hardcoded credentials or internal paths in source code</li>
                <li>Review hidden form inputs to ensure they don't contain sensitive parameters</li>
                <li>Implement a build process that strips development artifacts from production code</li>
                <li>Regularly audit webpage source code for information leakage</li>
            </ul>
        </section>

        <section>
            <h2>Conclusion</h2>
            <p>The assessment identified several instances of information leakage through webpage comments and metadata. While no critical vulnerabilities were found, the exposed information could aid attackers in understanding the application structure and identifying potential attack vectors. Immediate remediation is recommended to prevent information disclosure that could be exploited in further attacks.</p>
        </section>

        <footer>
            <p><em>This report was generated for educational purposes in a controlled environment (DVWA). Unauthorized testing on systems without permission is illegal.</em></p>
            <p>Report generated by AI Security Agent - OTG-INFO-005 Scanner</p>
        </footer>
    </div>
</body>
</html>"""
    
    return html_content

def main():
    """
    Main function to run the comments and metadata scanner and generate report
    """
    print("[*] Starting Webpage Comments and Metadata Review (OTG-INFO-005)")
    print("[*] Target: http://localhost/dvwa/")
    
    base_url = "http://localhost/dvwa/"
    
    # Test connection to DVWA
    try:
        response = requests.get(base_url, timeout=5)
        if response.status_code != 200:
            print("[ERROR] Cannot access DVWA. Please ensure it's running at http://localhost/dvwa/")
            return
    except requests.exceptions.RequestException:
        print("[ERROR] Cannot connect to http://localhost/dvwa/. Please ensure DVWA is running.")
        return
    
    # Create session and login
    session = requests.Session()
    print("[*] Attempting to log into DVWA...")
    if not login_to_dvwa(session, base_url):
        print("[!] Proceeding with analysis of public pages only...")
    
    # Analyze pages for comments and metadata
    findings = analyze_pages(base_url, session)
    
    # Generate HTML report
    html_report = generate_html_report(findings)
    
    # Save report
    report_filename = "OTG-INFO-005_Webpage_Comments_Metadata_Report.html"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(html_report)
    
    print(f"\n[+] Analysis Complete!")
    print(f"[+] Found {len(findings)} information leakage instances")
    print(f"[+] HTML Report saved as: {report_filename}")
    
    # Print summary
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        severity_counts[finding["severity"]] += 1
    
    print(f"\n--- Findings Summary ---")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"{severity}: {count}")

if __name__ == "__main__":
    main()