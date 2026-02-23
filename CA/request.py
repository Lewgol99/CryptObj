import requests
import json
from colorama import Fore

with open('server_url.json', 'r') as file:
    server = json.load(file)
CA_URL = f"http://{server['server']['addr']}:{server['server']['port']}"

with open('nodes.json', 'r') as file:
    nodes = json.load(file)

def submit_csr_to_ca(node_name):
    try:
        with open('csr.pem', 'r') as f:
            csr_pem = f.read()

        print(Fore.CYAN + f'📤 Submitting CSR for: {node_name}')

        response = requests.post(
            f'{CA_URL}/sign_csr',
            json={
                'csr': csr_pem,
                'node_name': node_name
            }
        )

        response.raise_for_status()
        cert_pem = response.json()['certificate']

        with open(f'{node_name}_certificate.pem', 'w') as f:
            f.write(cert_pem)

        print(Fore.GREEN + f'Success: Certificate saved as {node_name}_certificate.pem!')
        return True

    except Exception as e:
        print(Fore.RED + f'Error: Failed to receive Certificate from CA! {e}')
        return False

def fetch_all_certificates(own_node_name):
    for name in nodes:
        if name == own_node_name:
            continue
        try:
            response = requests.get(f'{CA_URL}/get_certificate/{name}')
            if response.status_code == 200:
                cert_pem = response.json().get('certificate')
                if cert_pem:
                    with open(f'{name}_certificate.pem', 'w') as f:
                        f.write(cert_pem)
                    print(Fore.GREEN + f'✓ Fetched and saved {name}_certificate.pem')
                else:
                    print(Fore.YELLOW + f'⚠ No certificate yet for {name}, will retry later')
            else:
                print(Fore.YELLOW + f'⚠ Could not fetch cert for {name} (status {response.status_code})')
        except Exception as e:
            print(Fore.RED + f'Error fetching cert for {name}: {e}')


def get_ca_status():
    try:
        response = requests.get(CA_URL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(Fore.RED + f'Error: Failed to connect to CA server! {e}')
        return None
