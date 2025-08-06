import requests
import os
import datetime
from urllib.parse import urljoin

def scan_metafiles():
    """
    Scans DVWA installation for common metafiles that may leak sensitive information
    """
    # DVWA base URL
    base_url = "http://localhost/dvwa/"
    
    # List of common metafiles and backup files to check
    metafiles = [
        ".git/HEAD",
        ".git/config",
        ".htaccess",
        ".htpasswd",
        "robots.txt",
        "backup.sql",
        "backup.zip",
        "backup.tar.gz",
        "config.php~",
        "config.php.bak",
        "config.old",
        "phpinfo.php",
        "test.php",
        ".env",
        ".DS_Store",
        "Thumbs.db",
        "README.md",
        "CHANGELOG.txt",
        "license.txt",
        "web.config",
        "config.php",
        "admin/config.php",
        "includes/config.php",
        "db.php",
        "database.php",
        "settings.php",
        "wp-config.php",
        "configuration.php"
    ]
    
    findings = []
    
    print(f"[+] Scanning {base_url} for metafiles...")
    
    for file_path in metafiles:
        url = urljoin(base_url, file_path)
        try:
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                print(f"[FOUND] {url} - Status: {response.status_code}")
                
                # Analyze content for sensitive data
                content = response.text.lower()
                severity = "Low"
                description = f"File accessible with {len(response.content)} bytes"
                
                # Critical findings
                if ".git/" in file_path:
                    severity = "Critical"
                    description = "Git repository metadata exposed"
                elif "config" in file_path and ("db_password" in content or "database" in content):
                    severity = "Critical"
                    description = "Configuration file with potential database credentials"
                elif "phpinfo.php" in file_path:
                    severity = "High"
                    description = "PHP info file accessible - exposes system information"
                elif ".htpasswd" in file_path:
                    severity = "High"
                    description = "Password file accessible"
                elif "robots.txt" in file_path:
                    severity = "Medium"
                    description = "Robots.txt file accessible - may reveal hidden paths"
                elif ".env" in file_path:
                    severity = "Critical"
                    description = "Environment file accessible - may contain secrets"
                
                findings.append({
                    "file": file_path,
                    "url": url,
                    "status": response.status_code,
                    "length": len(response.content),
                    "severity": severity,
                    "description": description,
                    "content_preview": response.text[:500] if len(response.text) > 500 else response.text
                })
            elif response.status_code == 403:
                print(f"[FORBIDDEN] {url} - Status: {response.status_code}")
            else:
                print(f"[NOT FOUND] {url} - Status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] {url} - {str(e)}")
            continue
    
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
    <title>OWASP OTG-INFO-003 - Webserver Metafile Review Report</title>
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
            <h1>OWASP Testing Guide - OTG-INFO-003</h1>
            <h2>Webserver Metafile Review Report</h2>
            <div class="report-meta">
                <div class="meta-item">
                    <strong>Target:</strong> http://localhost/dvwa/
                </div>
                <div class="meta-item">
                    <strong>Date:</strong> {timestamp}
                </div>
                <div class="meta-item">
                    <strong>Test ID:</strong> OTG-INFO-003
                </div>
                <div class="meta-item">
                    <strong>Tester:</strong> AI Security Agent
                </div>
            </div>
        </header>

        <section>
            <h2>Executive Summary</h2>
            <p>This report details the findings of a security assessment focused on identifying information leakage through webserver metafiles and backup files. The assessment targeted the DVWA application running on localhost to identify exposed files that could reveal sensitive configuration data, source code, or system information.</p>
        </section>

        <section>
            <h2>Test Details</h2>
            <p><strong>OWASP Test ID:</strong> OTG-INFO-003 - Review Webserver Metafiles for Information Leakage</p>
            <p>This test identifies sensitive information leakage through common webserver metafiles, backup files, and configuration files that may be accessible to unauthorized users.</p>
        </section>

        <section>
            <h2>Methodology</h2>
            <p>The assessment was performed using a custom Python script that systematically checked for the presence of common metafiles and backup files that are often left exposed in web applications. HTTP GET requests were made to each target file path, and accessible files were analyzed for sensitive content.</p>
            <p><strong>Tools Used:</strong> Custom Python Metafile Scanner</p>
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
                        <th>File</th>
                        <th>Status</th>
                        <th>Length</th>
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
                        <td><a href="{finding['url']}" target="_blank">{finding['file']}</a></td>
                        <td>{finding['status']}</td>
                        <td>{finding['length']}</td>
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
    for finding in findings:
        severity_class = get_severity_class(finding["severity"])
        html_content += f"""
        <section class="finding {severity_class}">
            <h3>{finding['file']}</h3>
            <p><strong>URL:</strong> <a href="{finding['url']}" target="_blank">{finding['url']}</a></p>
            <p><strong>Status:</strong> {finding['status']}</p>
            <p><strong>Length:</strong> {finding['length']} bytes</p>
            <p><strong>Severity:</strong> <span class="badge {severity_class}">{finding['severity']}</span></p>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Content Preview:</strong></p>
            <div class="content-preview">{finding['content_preview']}</div>
            <p><strong>Remediation:</strong> 
"""
        
        # Add remediation based on severity/file type
        if ".git" in finding['file']:
            html_content += "Remove .git directory from production environment or block access via web server configuration."
        elif "config" in finding['file']:
            html_content += "Ensure configuration files are not accessible via web requests and are stored outside the web root."
        elif "phpinfo.php" in finding['file']:
            html_content += "Remove phpinfo.php files from production servers as they expose sensitive system information."
        elif ".htpasswd" in finding['file']:
            html_content += "Store .htpasswd files outside the web root and ensure proper access controls are in place."
        else:
            html_content += "Remove or restrict access to unnecessary files and backup files from the web server."
        
        html_content += """
            </p>
        </section>
"""
    
    html_content += f"""
        <section>
            <h2>Remediation Recommendations</h2>
            <ul>
                <li>Remove all development files (.git, .env, backup files) from production environments</li>
                <li>Store configuration files outside the web root directory</li>
                <li>Implement proper access controls to prevent direct access to sensitive files</li>
                <li>Regularly audit web directories for exposed metafiles and backup files</li>
                <li>Use proper file permissions and web server configuration to restrict access</li>
                <li>Implement a deployment process that excludes development artifacts</li>
            </ul>
        </section>

        <section>
            <h2>Conclusion</h2>
            <p>The assessment identified several metafiles and backup files that are accessible and may expose sensitive information. Immediate remediation is recommended to prevent potential information leakage that could be exploited by attackers to gain deeper insights into the application structure and configuration.</p>
        </section>

        <footer>
            <p><em>This report was generated for educational purposes in a controlled environment (DVWA). Unauthorized testing on systems without permission is illegal.</em></p>
            <p>Report generated by AI Security Agent - OTG-INFO-003 Scanner</p>
        </footer>
    </div>
</body>
</html>"""
    
    return html_content

def main():
    """
    Main function to run the metafile scanner and generate report
    """
    print("[*] Starting Webserver Metafile Review (OTG-INFO-003)")
    print("[*] Target: http://localhost/dvwa/")
    
    # Test connection to DVWA
    try:
        response = requests.get("http://localhost/dvwa/", timeout=5)
        if response.status_code != 200:
            print("[ERROR] Cannot access DVWA. Please ensure it's running at http://localhost/dvwa/")
            return
    except requests.exceptions.RequestException:
        print("[ERROR] Cannot connect to http://localhost/dvwa/. Please ensure DVWA is running.")
        return
    
    # Scan for metafiles
    findings = scan_metafiles()
    
    # Generate HTML report
    html_report = generate_html_report(findings)
    
    # Save report
    report_filename = "OTG-INFO-003_Webserver_Metafile_Review_Report.html"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(html_report)
    
    print(f"\n[+] Scan Complete!")
    print(f"[+] Found {len(findings)} accessible metafiles")
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