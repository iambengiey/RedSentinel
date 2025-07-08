import requests
import json
import os

# Dynatrace API Configuration
API_URL = "https://YOUR_ENVIRONMENT_ID.live.dynatrace.com/api/v2/problems"
API_TOKEN = "dt0c01.YOUR_API_TOKEN"

headers = {
    "Authorization": f"Api-Token {API_TOKEN}",
    "Content-Type": "application/json"
}

params = {
    "pageSize": 10,
    "status": "open",
    "severityLevel": "PERFORMANCE"
}

response = requests.get(API_URL, headers=headers, params=params)

if response.status_code == 200:
    os.makedirs("data/api_inputs", exist_ok=True)
    with open("data/api_inputs/dynatrace_problems.json", "w") as f:
        json.dump(response.json(), f, indent=2)
    print("✅ Dynatrace problems data saved to data/api_inputs/dynatrace_problems.json")
else:
    print(f"❌ Failed to fetch from Dynatrace: {response.status_code} - {response.text}")
