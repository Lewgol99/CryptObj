from colorama import Fore
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes       
from cryptography import x509
from cryptography.hazmat.backends import default_backend     
import json
import pickle
from asymmetric_keys import Asymmetric_Keys
from ecc_keys import ECC_Keys
from ds_latency_monitor import DSLatencyMonitor

# ---------------------------------------------------------------------------
# TAGS - straight from the AnBx model (Phase 1 election, C2 = candidate)
#   C2 <-> C1 : tag1      C2 <-> C3 : tag3      C2 <-> C4 : tag5
# ---------------------------------------------------------------------------

NODE_ROLES = {
    '10.166.0.10': 'C1',
    '10.166.0.11': 'C2',
    '10.166.0.12': 'C3',
    '10.166.0.13': 'C4',
}
CHANNEL_TAGS = {
    frozenset(('C2', 'C1')): 'tag1',
    frozenset(('C2', 'C3')): 'tag3',
    frozenset(('C2', 'C4')): 'tag5',
}

def vote_tag(msg_type, sender_ip, recipient_ip):
    if msg_type not in ('request_vote', 'response_vote'):
        return None
    role_a = NODE_ROLES.get(sender_ip.split(':')[0])
    role_b = NODE_ROLES.get(recipient_ip.split(':')[0])
    return CHANNEL_TAGS.get(frozenset((role_a, role_b)))   # None if not a model channel

class DigitalSignature(Asymmetric_Keys):
    def __init__(self):
        self.latency_monitor = DSLatencyMonitor()
        super().__init__()

    def generate_Private_Key(self, key_param):
        if isinstance(key_param, int):
            super().Generate_Private_key(key_param)
        else:
            ecc = ECC_Keys()
            ecc.Generate_Private_Key(key_param)
            self.private_key = ecc.private_key

    def serialize_Private_key(self):
        try:
            fmt = serialization.PrivateFormat.TraditionalOpenSSL if isinstance(self.private_key, rsa.RSAPrivateKey) else serialization.PrivateFormat.PKCS8
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=fmt,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open('signing_private_key.pem', 'wb') as file:
                file.write(pem)
            print(Fore.GREEN + f'Success: Signing Private Key Generated!')
            return True
        except Exception as e:
            print(Fore.RED + f'Error: Signing Private Key Failed!')
            return None

    def Load_Private_Key(self):
        try:
            with open('signing_private_key.pem', 'rb') as file:
                self.private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=None
                )
            return self.private_key
        except Exception as e:
            print(Fore.RED + f'Error: Failed to Load Signing Private Key!')
            return None

    def load_public_key_from_pem(self, public_key_pem: str):
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            return public_key
        except Exception as e:
            print(Fore.RED + f'Error: Failed to Load Digital Signature Public Key!')
            return None

    def serialize_Public_key(self):
        try:
            public_key = self.private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open('signing_public_key.pem', 'wb') as file:
                file.write(pem)
            print(Fore.GREEN + f'Success: Signing Public Key Generated!')
            return True
        except Exception as e:
            print(Fore.RED + f'Error: Signing Public Key Failed!')
            return None

    def _do_sign(self, data: bytes):
        """Low-level sign — signs exactly the bytes passed in, no modification."""
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return self.private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
        else:
            return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def sign_raw(self, data: bytes):
        """Sign pre-built bytes exactly as-is. Used for handshake where the
        caller constructs the exact byte sequence the verifier will reconstruct."""
        try:
            self.latency_monitor.start_latency()
            signature = self._do_sign(data)
            self.latency_monitor.stop_latency('sign')
            return signature
        except Exception as e:
            print(Fore.RED + f'Error: Failed Signing Message! {e}')
            return None

    def sign(self, message: bytes, sender_ip: str, recipient_ip: str, other_ips: list):
        """Sign a Raft message, prepending sender+recipient IPs (and the channel tag for election messages)."""
        try:
            self.latency_monitor.start_latency()
            identity_prefix = ','.join([sender_ip, recipient_ip] + other_ips)

            try:
                decoded_payload = pickle.loads(message)
            except Exception:
                decoded_payload = message  # not a pickled dict (e.g. already bytes)

            msg_type = decoded_payload.get('type') if isinstance(decoded_payload, dict) else None
            tag = vote_tag(msg_type, sender_ip, recipient_ip)  # None if not a model channel
            tag_part = f';{tag}' if tag else ''

            print(Fore.CYAN + f'[IDENTITY] S={sender_ip} R={recipient_ip} O={other_ips}' + (f' TAG={tag}' if tag else ''))
            print(Fore.MAGENTA + f'[PAYLOAD] pre-sign structure: '
                  f'identity=({identity_prefix})' + (f' tag={tag}' if tag else '') + f' || data={decoded_payload}')

            signed_message = (identity_prefix + tag_part + '||').encode() + message
            signature = self._do_sign(signed_message)
            self.latency_monitor.stop_latency('sign')
            print(Fore.GREEN + f'Success: Message Signed!')
            return signature, signed_message
        except Exception as e:
            print(Fore.RED + f'Error: Failed Signing Message! {e}')
            return None

    def validate(self, public_key, message: bytes, signature: bytes):
        """Verify a signature over exactly the bytes in message."""
        try:
            self.latency_monitor.start_latency()
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature, message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            else:
                public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            self.latency_monitor.stop_latency('verify')
            print(Fore.GREEN + f'Success: Signature Verified!')
            return True
        except Exception as e:
            print(Fore.RED + f'Error: Signature Failed!')
            return False
