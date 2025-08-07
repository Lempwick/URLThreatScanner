import sys
import os
import requests
import urllib.parse
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

# Load API key from environment variable
API_KEY = os.getenv("IPQS_API_KEY")
if not API_KEY:
    raise EnvironmentError("Missing IPQS_API_KEY environment variable. Set it before running.")

class URLScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("URL Threat Scanner")
        self.setFixedSize(650, 500)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        title = QLabel("Malicious URL Scanner")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Enter a full URL (e.g., https://example.com)")
        self.input.setFont(QFont("Arial", 12))

        self.scan_button = QPushButton("Scan URL")
        self.scan_button.setFont(QFont("Arial", 12))
        self.scan_button.clicked.connect(self.scan_url)

        self.result_box = QTextEdit()
        self.result_box.setFont(QFont("Courier", 10))
        self.result_box.setReadOnly(True)

        for widget in (title, self.input, self.scan_button, self.result_box):
            layout.addWidget(widget)

        self.setLayout(layout)

    def scan_url(self):
        raw_url = self.input.text().strip()
        if not raw_url:
            self.result_box.setText("Please enter a valid URL.")
            return

        # Basic format check
        if not re.match(r'^https?://', raw_url):
            self.result_box.setText("Invalid URL format. Must start with http:// or https://")
            return

        encoded_url = urllib.parse.quote(raw_url, safe='')

        api_url = f"https://ipqualityscore.com/api/json/url/{API_KEY}/{encoded_url}"
        params = {
            "strictness": 1,
            "fast": "true",
            "timeout": 5
        }

        try:
            resp = requests.get(api_url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                if not data.get("success", False):
                    msg = data.get("message", "Unknown API failure.")
                    self.result_box.setText(f"API Error: {msg}")
                else:
                    self.display_result(raw_url, data)
            elif resp.status_code == 403:
                self.result_box.setText("Unauthorized: Check your API key.")
            else:
                self.result_box.setText(f"Unexpected HTTP Error: {resp.status_code}")
        except requests.exceptions.RequestException as e:
            self.result_box.setText(f"Network error: {str(e)}")

    def display_result(self, url, d):
        score = d.get("risk_score", "N/A")
        msg = (
            f"Scanning Results for: {url}\n\n"
            f"Unsafe: {d.get('unsafe')}\n"
            f"Suspicious: {d.get('suspicious')}\n"
            f"Phishing: {d.get('phishing')}\n"
            f"Malware: {d.get('malware')}\n"
            f"Risk Score: {score}/100\n"
            f"Category: {d.get('category')}\n"
            f"Domain: {d.get('domain')}\n"
            f"Domain Rank: {d.get('domain_rank')}\n"
            f"IP Address: {d.get('ip_address')}\n"
            f"Status Code: {d.get('status_code')}\n"
        )
        self.result_box.setText(msg)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = URLScanner()
    window.show()
    sys.exit(app.exec_())