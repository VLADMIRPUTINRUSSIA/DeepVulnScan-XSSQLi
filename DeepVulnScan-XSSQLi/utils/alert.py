import requests
from config.webhook import DISCORD_WEBHOOK_URL

def send_discord_alert(url, vuln_type, param, payload):
    content = (
        f"**[DeepVulnScan Alert]**\n"
        f"Vulnerability: **{vuln_type}**\n"
        f"URL: {url}\n"
        f"Parameter: {param}\n"
        f"Payload: `{payload}`\n"
    )
    data = {"content": content}
    try:
        r = requests.post(DISCORD_WEBHOOK_URL, json=data, timeout=10)
        if r.status_code != 204:
            print(f"[!] Failed to send Discord alert, status code: {r.status_code}")
    except Exception as e:
        print(f"[!] Exception sending Discord alert: {e}")
