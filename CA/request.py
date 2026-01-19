import requests
from colorama import Fore

CA_URL = "http://192.168.66.253:5000"

def submit_csr_to_ca():
    try:
        with open('csr.pem', 'r') as f:
            csr_pem = f.read()
        
        response = requests.post(f'{CA_URL}/sign_csr', json={'csr': csr_pem})  
        response.raise_for_status()

        cert_pem = response.json()['certificate']
        with open('certificate.pem', 'w') as f:
            f.write(cert_pem)
        print(Fore.GREEN + 'Success: Certificate received from CA!') 
        return True
    except Exception as e:
        print(Fore.RED + f'Error: Failed to receive Certificate from CA! {e}') 
        return False

def get_ca_status():
    try:
        response = requests.get(CA_URL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(Fore.RED + f'Error: Failed to connect to CA server! {e}')
        return None

status = get_ca_status()
print(status)
