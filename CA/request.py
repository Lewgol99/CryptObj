import requests
import json
import time
import threading
from colorama import Fore

with open('server_url.json', 'r') as file:
    server = json.load(file)
CA_URL = f"http://{server['server']['addr']}:{server['server']['port']}"

with open('scale_nodes.json', 'r') as file:
    nodes = json.load(file)

def wait_for_ca(max_retries=30, delay=5):
    for attempt in range(max_retries):
        try:
            response = requests.get(CA_URL, timeout=5)
            if response.status_code == 200:
                print(Fore.GREEN + 'CA is ready!')
                return True
        except Exception as e:
            print(Fore.YELLOW + f'Waiting for CA... ({attempt+1}/{max_retries})')
            time.sleep(delay)
    print(Fore.RED + 'Error: CA never became ready!')
    return False

def submit_csr_to_ca(node_name, max_retries=30, delay=10):
    if not wait_for_ca():
        return False
    for attempt in range(max_retries):
        try:
            with open('csr.pem', 'r') as f:
                csr_pem = f.read()
            print(Fore.CYAN + f'Submitting CSR for: {node_name} (attempt {attempt+1}/{max_retries})')
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
            if attempt < max_retries - 1:
                print(Fore.YELLOW + f'Retrying in {delay} seconds...')
                time.sleep(delay)
    print(Fore.RED + f'Error: Gave up after {max_retries} attempts for {node_name}')
    return False

def fetch_one_certificate(name, max_retries=30, delay=5):
    for attempt in range(max_retries):
        try:
            response = requests.get(f'{CA_URL}/get_certificate/{name}', timeout=5)
            if response.status_code == 200:
                cert_pem = response.json().get('certificate')
                if cert_pem:
                    with open(f'{name}_certificate.pem', 'w') as f:
                        f.write(cert_pem)
                    print(Fore.GREEN + f'✓ Fetched {name}_certificate.pem')
                    return True
                else:
                    print(Fore.YELLOW + f'No certificate yet for {name}, retrying in {delay}s...')
                    time.sleep(delay)
            else:
                print(Fore.YELLOW + f'Could not fetch cert for {name} (status {response.status_code}), retrying...')
                time.sleep(delay)
        except Exception as e:
            print(Fore.RED + f'Error fetching cert for {name}: {e}')
            if attempt < max_retries - 1:
                time.sleep(delay)
    return False

def fetch_all_certificates(own_node_name):
    print(Fore.CYAN + 'Fetching all certificates in parallel...')
    threads = []
    for name in nodes:
        if name == own_node_name:
            continue
        t = threading.Thread(target=fetch_one_certificate, args=(name,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print(Fore.GREEN + 'All certificates fetched!')

def get_ca_status():
    try:
        response = requests.get(CA_URL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(Fore.RED + f'Error: Failed to connect to CA server! {e}')
        return None
