import os
from datetime import datetime
from fpdf import FPDF
import requests
import urllib3

# Suppress SSL warnings (if needed for testing, but avoid in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wazuh API details
api_url = "https://10.255.255.21"  # Replace with your server IP or domain
endpoint = "/security/events"
headers = {
    'Authorization': 'Bearer <TOKEN> ',  # Replace with your token
    'Content-Type': 'application/json'
}

# Fetch alerts data from the Wazuh API
try:
    response = requests.get(f"{api_url}{endpoint}?limit=50", headers=headers, verify=False)  # Change verify=True to validate SSL certificate
    response.raise_for_status()  # Raise an exception for HTTP errors
    data = response.json()
except requests.exceptions.HTTPError as err:
    print(f"Error fetching data: {err}")
    exit()

# Create PDF Report
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, 'Wazuh Alerts Report', border=False, ln=True, align='C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, title, ln=True, align='L')

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 10, body)

pdf = PDF()
pdf.add_page()

# Check if 'data' and 'alerts' keys exist in the response
if 'data' in data and 'alerts' in data['data']:
    for alert in data['data']['alerts']:
        alert_id = alert.get('id', 'N/A')
        severity = alert.get('rule', {}).get('level', 'N/A')
        description = alert.get('rule', {}).get('description', 'No description available')
        timestamp = alert.get('timestamp', 'N/A')
        rule = alert.get('rule', {}).get('id', 'N/A')

        pdf.chapter_title(f"Alert ID: {alert_id}")
        body = (
            f"Rule ID: {rule}\n"
            f"Description: {description}\n"
            f"Severity: {severity}\n"
            f"Timestamp: {timestamp}"
        )
        pdf.chapter_body(body)
else:
    print("No alerts found in the response.")
    exit()

# Save report to a dedicated folder with a timestamped filename
output_folder = os.path.expanduser("~/wazuh_reports")
os.makedirs(output_folder, exist_ok=True)
filename = f"{output_folder}/wazuh_alerts_{datetime.now().strftime('%Y-%m-%d')}.pdf"
pdf.output(filename)
print(f"Report saved to {filename}")
