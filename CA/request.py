import requests

response = requests.get("http://0.0.0.0:5000/")
print(response.json())
