import requests
from bs4 import BeautifulSoup

# Configuration
url = 'http://localhost/dvwa/'
login_data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
security_level = 'low'

# Session setup
session = requests.Session()

# Get the login page to retrieve the user token
response = session.get(url + 'login.php')
soup = BeautifulSoup(response.text, 'html.parser')
user_token = soup.find('input', {'name': 'user_token'}).get('value')

# Update login data with the token
login_data['user_token'] = user_token

# Login
response = session.post(url + 'login.php', data=login_data)
if 'Welcome' not in response.text:
    print("Login failed")
    exit()

# Set security level
response = session.get(url + f'security.php?security={security_level}&phpids=0')
if security_level not in response.text:
    print("Security level not set")
    exit()

# Header analysis
response = session.get(url)
headers = response.headers
server = headers.get('Server', '')
x_powered_by = headers.get('X-Powered-By', '')
print(f"Server: {server}")
print(f"X-Powered-By: {x_powered_by}")

# Common files check
common_files = ['/server-status', '/server-info', '/phpinfo.php', '/test.php', '/.well-known/security.txt']
for file in common_files:
    response = session.head(url + file)
    if response.status_code < 400:
        print(f"Found: {file}")

# Banner grabbing (simplified)
import socket
host = 'localhost'
port = 80
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))
sock.send(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
response = sock.recv(4096)
print(response.decode())

# Framework detection
# Check for framework-specific files
framework_files = ['/README.md', '/CHANGELOG.txt']
for file in framework_files:
    response = session.head(url + file)
    if response.status_code < 400:
        print(f"Found framework file: {file}")

# Generate report (simplified)
report = '''
<!DOCTYPE html>
<html>
<head>
    <title>Web Server Fingerprint Report</title>
</head>
<body>
    <section id="executive-summary">
        <h1>Executive Summary</h1>
        <p>Web server fingerprinting test completed.</p>
    </section>
    <section id="test-details">
        <h1>Test Details</h1>
        <p>Tested against DVWA at http://localhost/dvwa/</p>
    </section>
    <section id="findings">
        <h1>Findings</h1>
        <p>Server: {server}</p>
        <p>X-Powered-By: {x_powered_by}</p>
    </section>
    <section id="risk-assessment">
        <h1>Risk Assessment</h1>
        <p>Low risk identified.</p>
    </section>
    <section id="recommendations">
        <h1>Recommendations</h1>
        <p>Update server headers.</p>
    </section>
    <section id="evidence">
        <h1>Evidence</h1>
        <p>See console output.</p>
    </section>
</body>
</html>
'''.format(server=server, x_powered_by=x_powered_by)
with open('report.html', 'w') as f:
    f.write(report)