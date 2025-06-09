import requests
import json

# Data masukan
test_data = {
    "Source Port": 12345,
    "Destination Port": 80,
    "Packet Length": 512,
    "Payload Data": "whoami; id | xxd -ps",
    "Timestamp": "2025-06-07 11:00:00",
    "Malware Indicators": "None",
    "Protocol": "TCP",
    "Traffic Type": "HTTP"
}

# Kirim permintaan
response = requests.post('http://localhost:5000/predict', json=test_data)
print("Status Code:", response.status_code)
print("Response:", response.json())

# Uji data berbahaya
test_data_malicious = {
    "Source Port": 54321,
    "Destination Port": 80,
    "Packet Length": 1024,
    "Payload Data": "powershell.exe -EncodedCommand UABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFA",
    "Timestamp": "2025-06-07 12:00:00",
    "Malware Indicators": "None",
    "Protocol": "None",
    "Traffic Type": "HTTP"
}
response_malicious = requests.post('http://localhost:5000/predict', json=test_data_malicious)
print("\nStatus Code (Malicious):", response_malicious.status_code)
print("Response (Malicious):", response_malicious.json())