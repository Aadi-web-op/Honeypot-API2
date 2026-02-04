import requests
import json
import time

url = "http://localhost:8000/analyze"
headers = {
    "x-api-key": "honeypot_key_2026_eval",
    "Content-Type": "application/json"
}

payload = {
    "sessionId": "test-session-123",
    "message": {
        "sender": "scammer",
        "text": "Urgent: Your bank account is blocked. Click here https://bad-link.com to verify.",
        "timestamp": 123456789
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "sms",
        "language": "en",
        "locale": "IN"
    }
}

try:
    print("Sending request...")
    response = requests.post(url, headers=headers, json=payload)
    print(f"Status Code: {response.status_code}")
    print("Response JSON:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
