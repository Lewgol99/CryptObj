import requests

response = requests.get("http://10.100.0.186:5000/")
print(response.json())
