import requests
from colorama import Fore

CA_URL = "http://192.168.66.252:5000"

def get_ca_status():
    try:
        response = requests.get(CA_URL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(Fore.RED + f'Error: Failed to connect to CA server!')
        return None

status = get_ca_status()
print(status)
