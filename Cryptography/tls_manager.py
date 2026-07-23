import json
import os
from tls_session import TLS_Session
from latency_monitor import LatencyMonitor
 
CA_CERT_FILE = 'certificate.pem'
SELF_KEY_FILE = 'pki_private_key.pem'

def _select_cipher_suite():
    with open('tls_ciphers.json', 'r') as f:
        suites = json.load(f)['cipher_suites']
    selected = os.environ.get('SELECTED_CIPHER', '')
    matches = [s for s in suites if selected.upper() in s.upper()]
    return matches[0] if matches else ':'.join(suites)

class TLS_Manager:
    def __init__(self):
        nodes_file = 'scale_nodes.json' if os.path.exists('scale_nodes.json') else 'nodes.json'
        with open(nodes_file, 'r') as f:
            nodes = json.load(f)
 
        self.self_node_name = os.environ['NODE_NAME']
        self.self_address = f"{nodes[self.self_node_name]['addr']}:{nodes[self.self_node_name]['port']}"
        self.peer_addresses = {
            name: f"{info['addr']}:{info['port']}"
            for name, info in nodes.items() if name != self.self_node_name
        }
        self.latency_monitor = LatencyMonitor()
        self._sessions = {}
        self.cipher_suite = _select_cipher_suite()
        self.cipher_name = os.environ.get('SELECTED_CIPHER', '?')
        self.curve_name = os.environ.get('USE_TLS')
     
    def _is_client_for(self, peer_node_name):
        return self.self_address > self.peer_addresses[peer_node_name]
 
    def session_for(self, peer_node_name):
        self._sessions[peer_node_name] = TLS_Session(
            self_node_name=self.self_node_name,
            peer_node_name=peer_node_name,
            is_client=self._is_client_for(peer_node_name),
            self_cert_file=f'{self.self_node_name}_certificate.pem',
            self_key_file=SELF_KEY_FILE,
            ca_cert_file=CA_CERT_FILE,
            latency_monitor=self.latency_monitor,
            cipher_suite=self.cipher_suite,
            cipher_name=self.cipher_name,
            curve_name=self.curve_name,
        )
        return self._sessions[peer_node_name]

    def _load_certificates(self):
        pass
