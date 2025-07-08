import requests
import json
import os

# Grafana Loki API Configuration
LOKI_URL = "http://localhost:3100/loki/api/v1/query_range"
query = '{job="varlogs"}'

params = {
    "query": query,
    "limit": 100,
    "start": "now-1h",
    "end": "now"
}

response = requests.get(LOKI_URL, params=params)

if response.status_code == 200:
    os.makedirs("data/api_inputs", exist_ok=True)
    with open("data/api_inputs/grafana_logs.json", "w") as f:
        json.dump(response.json(), f, indent=2)
    print("✅ Grafana Loki data saved to data/api_inputs/grafana_logs.json")
else:
    print(f"❌ Failed to fetch from Grafana Loki: {response.status_code} - {response.text}")
