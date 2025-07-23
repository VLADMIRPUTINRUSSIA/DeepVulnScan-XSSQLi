import csv
import os
from datetime import datetime, timezone, timedelta

class Logger:
    def __init__(self):
        self.logfile = 'logs/results.csv'
        if not os.path.exists('logs'):
            os.makedirs('logs')
        if not os.path.isfile(self.logfile):
            with open(self.logfile, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp_UTC', 'Timestamp_CEST', 'Timestamp_Zulu', 'URL', 'Vulnerability', 'Parameter', 'Payload'])

    def log(self, message):
        print(f"[LOG] {message}")

    def log_vuln(self, url, vuln_type, param, payload):
        utc = datetime.now(timezone.utc)
        cest = utc + timedelta(hours=2)
        zulu = utc  # Zulu = UTC
        with open(self.logfile, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                utc.isoformat(),
                cest.isoformat(),
                zulu.isoformat(),
                url,
                vuln_type,
                param,
                payload
            ])
        self.log(f"Found {vuln_type} vulnerability on {url} - param: {param} - payload: {payload}")
