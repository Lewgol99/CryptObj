import requests

response = requests.get("http://192.168.66.252:5000/")
print(response.json())
