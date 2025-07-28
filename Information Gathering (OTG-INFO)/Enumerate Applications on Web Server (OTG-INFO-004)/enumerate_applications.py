import requests
from bs4 import BeautifulSoup

# Configuration
url = 'http://localhost/dvwa/'
login_data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
security_level = 'low'

# Session setup
session = requests.Session()

# Login (reusing code from previous script)
def login():
    # Get login page to retrieve user token
    response = session.get(url + 'login.php')
    soup = BeautifulSoup(response.text, 'html.parser')
    user_token = soup.find('input', {'name': 'user_token'}).get('value')
    login_data['user_token'] = user_token

    # Login
    response = session.post(url + 'login.php', data=login_data)
    if 'Welcome' not in response.text:
        print("Login failed")
        exit()

login()

# Set security level
response = session.get(url + f'security.php?security={security_level}&phpids=0')
if security_level not in response.text:
    print("Security level not set")
    exit()

# Common directories and files to check
common_directories = ['/admin/', '/backup/', '/config/', '/install/', '/logs/', '/includes/', '/uploads/', '/assets/', '/wp-admin/', '/drupal/']
common_files = ['robots.txt', 'crossdomain.xml', 'security.txt', 'web.config', '.htaccess', '.env']
sensitive_files = ['*.bak', '*.old', '*.zip', '.git/HEAD', '.svn/entries']
admin_interfaces = ['/phpmyadmin/', '/adminer.php', '/mysql/']
dev_files = ['test.php', 'info.php', 'console.php']
metadata_files = ['package.json', 'composer.json', 'bower.json']

# Enumerate directories and files
findings = []

def check_paths(paths):
    for path in paths:
        response = session.head(url + path)
        if response.status_code < 400:
            findings.append({
                'title': f"Found {path}",
                'path': url + path,
                'status': response.status_code,
                'response': response.text[:100]
            })

check_paths(common_directories)
check_paths(common_files)
check_paths(admin_interfaces)
check_paths(dev_files)
check_paths(metadata_files)

# Discover content
def discover_content():
    # Check HTML comments
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        if 'version' in comment or 'admin' in comment:
            findings.append({
                'title': "HTML Comment Found",
                'path': url,
                'status': response.status_code,
                'response': str(comment)
            })

from bs4 import Comment
discover_content()

# Generate report
report_section = '''
<section id="application-enumeration">
    <h2>OTG-INFO-004: Application Enumeration</h2>
'''
for finding in findings:
    report_section += f'''
    <div class="finding">
        <h3>{finding['title']}</h3>
        <p><strong>Path</strong>: {finding['path']}</p>
        <p><strong>Status Code</strong>: {finding['status']}</p>
        <pre>{finding['response']}</pre>
    </div>
'''
report_section += '</section>'

# Append to existing report
report_file = 'OWASP_Web_Server_Fingerprint_Report.html'
try:
    with open(report_file, 'a') as f:
        f.write(report_section)
except FileNotFoundError:
    # Create new report if not exists
    with open(report_file, 'w') as f:
        f.write('<html><body>')
        f.write(report_section)
        f.write('</body></html>')

print(f"Report updated: {report_file}")