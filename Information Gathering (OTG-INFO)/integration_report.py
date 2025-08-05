import datetime

def generate_html_report(test_results):
    """Generate OWASP-style HTML report with detailed test status"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate test cards
    test_cards_html = ""
    for test in test_results:
        status_class = "success" if test['status'] == "Success" else "failed"
        test_cards_html += f"""
        <div class="test-card {status_class}">
            <h3>{test['test_id']}: {test['name']}</h3>
            <div class="test-status">Status: {test['status']}</div>
            <div class="findings-count">Findings: {len(test['findings'])}</div>
        </div>
        """
    
    # Generate findings sections
    findings_html = ""
    for test in test_results:
        status_class = test['status'].lower()
        findings_html += f"""
        <section class="test-section">
            <div class="section-header">
                <h2>
                    {test['test_id']}: {test['name']}
                    <span class="test-status-badge {status_class}">{test['status']}</span>
                </h2>
            </div>
            <div class="section-content">
        """
        
        if test['error_info']:
            findings_html += f"""
            <div class="error-info">
                <h3>Test Execution Error</h3>
                <pre>{test['error_info']}</pre>
            </div>
            """
        
        for finding in test['findings']:
            risk_class = f"risk-{finding['risk'].lower()}" if finding['risk'] != 'Info' else 'risk-info'
            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <h3>{finding['title']}</h3>
                    <div class="risk-label {risk_class}">{finding['risk']} Risk</div>
                </div>
                <p><strong>Description:</strong> {finding['description']}</p>
                <p><strong>URL:</strong> <span class="url">{finding['url']}</span></p>
                <div class="evidence-container">
                    <h4>Evidence:</h4>
                    <pre>{finding['evidence']}</pre>
                </div>
            </div>
            """
        
        findings_html += "</div></section>"
    
    # Full HTML template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP Configuration Test Report</title>
    <style>
        /* Base styles */
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background-color: #222;
            color: white;
            padding: 2rem;
            text-align: center;
            margin-bottom: 2rem;
            border-bottom: 5px solid #c00;
            border-radius: 5px;
        }}
        
        h1, h2, h3 {{
            color: #222;
        }}
        
        .report-meta {{
            background-color: #e9ecef;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .report-meta div {{
            background-color: white;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            font-size: 0.9rem;
        }}
        
        /* Test summary cards */
        .test-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .test-card {{
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 1.5rem;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        
        .test-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        
        .test-card.success {{
            border-top: 4px solid #28a745;
        }}
        
        .test-card.failed {{
            border-top: 4px solid #dc3545;
        }}
        
        .test-status {{
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .test-card.success .test-status {{
            color: #28a745;
        }}
        
        .test-card.failed .test-status {{
            color: #dc3545;
        }}
        
        /* Test sections */
        .test-section {{
            margin-bottom: 2.5rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
            background-color: white;
        }}
        
        .section-header {{
            background-color: #343a40;
            color: white;
            padding: 1.2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .test-status-badge {{
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: bold;
        }}
        
        .test-status-badge.success {{
            background-color: #28a745;
        }}
        
        .test-status-badge.failed {{
            background-color: #dc3545;
        }}
        
        .section-content {{
            padding: 1.8rem;
        }}
        
        /* Findings styles */
        .finding {{
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.8rem;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .risk-label {{
            padding: 0.3rem 0.8rem;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85rem;
        }}
        
        .risk-high {{
            background-color: #ffcccc;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }}
        
        .risk-medium {{
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeeba;
        }}
        
        .risk-low {{
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }}
        
        .risk-info {{
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }}
        
        .url {{
            font-family: monospace;
            background-color: #e9ecef;
            padding: 0.3rem 0.5rem;
            border-radius: 3px;
            word-break: break-all;
            display: inline-block;
            margin: 0.3rem 0;
        }}
        
        pre {{
            background-color: #2d2d2d;
            color: #f8f8f2;
            padding: 1.2rem;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Consolas', monospace;
            margin-top: 0.8rem;
            max-height: 300px;
            overflow-y: auto;
            line-height: 1.4;
        }}
        
        .error-info {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 5px;
            padding: 1.2rem;
            margin-bottom: 1.5rem;
        }}
        
        footer {{
            text-align: center;
            margin-top: 3rem;
            padding: 1.5rem;
            color: #6c757d;
            font-size: 0.9rem;
            border-top: 1px solid #dee2e6;
        }}
        
        /* Responsive design */
        @media (max-width: 768px) {{
            .test-summary {{
                grid-template-columns: 1fr;
            }}
            
            .section-header {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .test-status-badge {{
                margin-top: 0.5rem;
            }}
            
            .finding-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }}
            
            .risk-label {{
                align-self: flex-start;
            }}
        }}
    </style>
</head>
<body>
    <header>
        <h1>OWASP Configuration & Deployment Test Report</h1>
        <p>Comprehensive security assessment of application configuration</p>
    </header>
    
    <div class="report-meta">
        <div><strong>Generated:</strong> {timestamp}</div>
        <div><strong>Target:</strong> {BASE_URL}</div>
        <div><strong>Tests:</strong> OTG-CONFIG-002 to OTG-CONFIG-008</div>
    </div>
    
    <section class="executive-summary">
        <h2>Executive Summary</h2>
        <div class="test-summary">
            {test_cards_html}
        </div>
    </section>
    
    <section class="detailed-findings">
        <h2>Detailed Test Results</h2>
        {findings_html}
    </section>
    
    <footer>
        <p>Generated by OWASP Security Testing Toolkit | {timestamp}</p>
        <p>Report includes findings from all completed tests with error details for failed tests</p>
    </footer>
</body>
</html>
    """
    
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return REPORT_FILE

def main():
    # Example test results structure
    test_results = [
        {
            'test_id': 'OTG-INFO-XXX',
            'name': 'Comprehensive Web Application Analysis',
            'status': 'Success',
            'findings': [
                {
                    'title': 'Form Found',
                    'description': 'A form was found on the login page.',
                    'url': 'http://example.com/login',
                    'evidence': '<form action="/login" method="post">...</form>',
                    'risk': 'Info'
                }
            ],
            'error_info': ''
        },
        # Add other test results here...
    ]
    
    report_file = generate_html_report(test_results)
    print(f"Report generated: {report_file}")

if __name__ == "__main__":
    main()