tls_session import TLS_Session
 
CA_CERT_FILE = 'certificate.pem'
SELF_KEY_FILE = 'pki_private_key.pem'
 
class TLS_Manager:
    def __init__(self, self_node_name, self_address, peer_addresses):
        self.self_node_name = self_node_name
        self.self_address = self_address
        self.peer_addresses = peer_addresses
        self._sessions = {}
 
    def _is_client_for(self, peer_node_name):
        return self.self_address > self.peer_addresses[peer_node_name]
 
    def session_for(self, peer_node_name):
        if peer_node_name not in self._sessions:
            self._sessions[peer_node_name] = PeerTLSSession(
                self_node_name=self.self_node_name,
                peer_node_name=peer_node_name,
                is_client=self._is_client_for(peer_node_name),
                self_cert_file=f'{self.self_node_name}_certificate.pem',
                self_key_file=SELF_KEY_FILE,
                ca_cert_file=CA_CERT_FILE,
            )
        return self._sessions[peer_node_name]
