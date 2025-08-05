import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

# Framework signatures
FRAMEWORK_SIGNATURES = {
    'Laravel': {'files': ['artisan'], 'headers': ['x-laravel-version']},
    'Symfony': {'cookies': ['symfony'], 'dirs': ['/app/config']},
    'Django': {'comments': ['Django'], 'files': ['manage.py']},
    'Express': {'files': ['package.json'], 'comments': ['Express']}
}

# Target URL and credentials
URL = 'http://localhost/dvwa/'
LOGIN_URL = URL + 'login.php'
SECURITY_URL = URL + 'security.php'
USERNAME = 'admin'
PASSWORD = 'password'
SECURITY_LEVEL = 'low'

# Session management
session = requests.Session()

# Login function
def login():
    response = session.get(LOGIN_URL)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']
    data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login',
        'user_token': user_token
    }
    session.post(LOGIN_URL, data=data)

# Set security level
def set_security_level():
    response = session.get(SECURITY_URL)
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'})['value']
    data = {
        'security': SECURITY_LEVEL,
        'seclev_submit': 'Submit',
        'user_token': user_token
    }
    session.post(SECURITY_URL, data=data)

# Crawl the application
def crawl(url):
    visited = set()
    to_visit = [url]
    forms = []
    url_params = set()
    ajax_endpoints = set()
    file_uploads = set()
    
    while to_visit:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)
        response = session.get(current_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find forms
        for form in soup.find_all('form'):
            forms.append({
                'action': form.get('action'),
                'method': form.get('method', 'get'),
                'inputs': [(inp.get('name'), inp.get('type')) for inp in form.find_all('input')]
            })
            
        # Find URL parameters
        for link in soup.find_all('a', href=True):
            href = link['href']
            if '?' in href:
                url_params.add(href)
                
        # Find AJAX endpoints (simplified example)
        # This would require more advanced techniques, possibly using Selenium
        # For now, just a placeholder
        ajax_endpoints.add(current_url + '/ajax')
        
        # Find file upload points
        for form in soup.find_all('form', enctype='multipart/form-data'):
            file_uploads.add(current_url)
            
        # Add new links to visit
        for link in soup.find_all('a', href=True):
            next_url = urljoin(current_url, link['href'])
            if next_url.startswith(URL) and next_url not in visited:
                to_visit.append(next_url)
                
    # Return results
    return {
        'forms': forms,
        'url_params': list(url_params),
        'ajax_endpoints': list(ajax_endpoints),
        'file_uploads': list(file_uploads)
    }

# Framework fingerprinting
def fingerprint_framework():
    response = session.get(URL)
    headers = response.headers
    cookies = session.cookies.get_dict()
    content = response.text

    for framework, signatures in FRAMEWORK_SIGNATURES.items():
        if 'headers' in signatures:
            for header in signatures['headers']:
                if header in headers:
                    return framework
        if 'cookies' in signatures:
            for cookie in signatures['cookies']:
                if cookie in cookies:
                    return framework
        if 'comments' in signatures:
            for comment in signatures['comments']:
                if re.search(comment, content):
                    return framework
        if 'files' in signatures:
            for file in signatures['files']:
                if session.get(URL + file).status_code == 200:
                    return framework
        if 'dirs' in signatures:
            for dir in signatures['dirs']:
                if session.get(URL + dir).status_code == 200:
                    return framework
    return 'Unknown'

# Fingerprint web application
def fingerprint_web_app():
    response = session.get(URL)
    headers = response.headers
    content = response.text
    soup = BeautifulSoup(content, 'html.parser')
    
    server = headers.get('Server', '')
    x_powered_by = headers.get('X-Powered-By', '')
    meta_tags = soup.find_all('meta')
    
    app_info = {
        'server': server,
        'x_powered_by': x_powered_by,
        'meta': [(tag.get('name'), tag.get('content')) for tag in meta_tags]
    }
    
    return app_info

# Function to generate HTML report
def generate_report(data):
    html = """
    <html>
    <head>
        <title>Web Application Analysis Report</title>
    </head>
    <body>
        <h1>Web Application Analysis Report</h1>
        <h2>1. Framework Fingerprinting</h2>
        <p>Detected framework: {framework}</p>
        <h2>2. Application Crawling</h2>
        <h3>Forms</h3>
        <pre>{forms}</pre>
        <h3>URL Parameters</h3>
        <pre>{url_params}</pre>
        <h3>AJAX Endpoints</h3>
        <pre>{ajax_endpoints}</pre>
        <h3>File Upload Points</h3>
        <pre>{file_uploads}</pre>
        <h2>3. Web Application Fingerprinting</h2>
        <pre>{app_info}</pre>
    </body>
    </html>
    """.format(
        framework=data['framework'],
        forms=data['forms'],
        url_params=data['url_params'],
        ajax_endpoints=data['ajax_endpoints'],
        file_uploads=data['file_uploads'],
        app_info=data['app_info']
    )
    
    with open('report.html', 'w') as f:
        f.write(html)

# Main function
def main():
    login()
    set_security_level()
    framework = fingerprint_framework()
    
    # Crawl the application
    crawl_data = crawl(URL)
    
    # Fingerprint web application
    app_info = fingerprint_web_app()
    
    # Generate report
    data = {
        'framework': framework,
        'forms': crawl_data['forms'],
        'url_params': crawl_data['url_params'],
        'ajax_endpoints': crawl_data['ajax_endpoints'],
        'file_uploads': crawl_data['file_uploads'],
        'app_info': app_info
    }
    generate_report(data)
    
    print("Report generated: report.html")

if __name__ == '__main__':
    main()