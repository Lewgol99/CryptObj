import requests
import json
from colorama import Fore

with open('server_url.json', 'r') as file:
    server = json.load(file)

CA_URL = f"http://{server['server']['addr']}:{server['server']['port']}"

def submit_csr_to_ca(node_name):
    try:
        with open('csr.pem', 'r') as f:
            csr_pem = f.read()
        
        print(Fore.CYAN + f'📤 Submitting CSR for: {node_name}')
        
        # Send CSR and node_name to CA
        response = requests.post(
            f'{CA_URL}/sign_csr',
            json={
                'csr': csr_pem,
                'node_name': node_name
            }
        )
        
        response.raise_for_status()
        cert_pem = response.json()['certificate']
        
        # Save with node name
        with open(f'{node_name}_certificate.pem', 'w') as f:
            f.write(cert_pem)
        
        print(Fore.GREEN + f'Success: Certificate saved as {node_name}_certificate.pem and certificate.pem!') 
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
