import json
import os
from tls_session import TLS_Session
from latency_monitor import LatencyMonitor
 
CA_CERT_FILE = 'certificate.pem'
SELF_KEY_FILE = 'pki_private_key.pem'

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
        )
        return self._sessions[peer_node_name]

    def _load_certificates(self):
        pass
