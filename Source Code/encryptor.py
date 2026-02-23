from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from colorama import Fore, Style, init
import struct, glob
import time

init(autoreset=True)
HAS_CRYPTO = True  # Required by pysyncobj

# Required by pysyncobj
def getEncryptor(password):
    return RSAEncryptor(password)

class RSAEncryptor:  # Required by pysyncobj
    def __init__(self, password=None):  # Required by pysyncobj
        with open('pki_private_key.pem', 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), 
                password=None,
                backend=default_backend()
            )
        self.public_keys = self._load_all_certificates()
        self.enabled = len(self.public_keys) >= 3
        print(f"Loaded {len(self.public_keys)} RSA certs, encrypt={'ON' if self.enabled else 'OFF'}")

    def _load_all_certificates(self):
        public_keys = {}
        for cert_file in glob.glob('*_certificate.pem'):
            try:
                with open(cert_file, 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    pub_key = cert.public_key()
                    if isinstance(pub_key, rsa.RSAPublicKey):
                        public_keys[cert_file.replace('_certificate.pem', '')] = pub_key
                    else:
                        print(f"[SKIP] {cert_file}: Not RSA cert ({type(pub_key).__name__})")
            except:
                pass
        return public_keys

    def _load_certificates(self):
        new_certs = self._load_all_certificates()
        if len(new_certs) > len(self.public_keys):
            print(f"[CERT REFRESH] Found {len(new_certs) - len(self.public_keys)} new certificates!")
            self.public_keys = new_certs
            self.enabled = len(self.public_keys) >= 3
            if self.enabled:
                print(f"[ENCRYPTION] Now enabled with {len(self.public_keys)} certificates!")

    _raft_context = ""

    @classmethod
    def set_context(cls, label: str):
        cls._raft_context = label

    def encrypt_at_time(self, data, ts):  # Required by pysyncobj
        time.sleep(1)  # Use time lib to slow the system
        try:
            ctx = f"  ← {self._raft_context}" if self._raft_context else ""
            if not self.enabled:
                print(f"SEND {len(data):>5}B  [no encryption]{ctx}")
                return struct.pack('!Q', ts) + data

            fernet_key = Fernet.generate_key()
            encrypted_data = Fernet(fernet_key).encrypt(data)
            packet = struct.pack('!Q', ts) + struct.pack('!H', len(self.public_keys))
            for public_key in self.public_keys.values():
                encrypted_key = public_key.encrypt(
                    fernet_key,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                packet += struct.pack('!H', len(encrypted_key)) + encrypted_key
            packet += encrypted_data
            
            hex_fp = packet[:20].hex()
            print(f"SEND {len(data):>5}B → {len(packet):>5}B  "
                  f"{Fore.RED}{hex_fp}…{Style.RESET_ALL}{ctx}")
            return packet

        except Exception as e:
            print(f"[ERROR] Encrypt: {e}")
            raise

    def decrypt(self, packet):  # Required by pysyncobj
        try:
            if len(packet) < 14:
                return packet[8:]
            try:
                num_recipients = struct.unpack('!H', packet[8:10])[0]
                if num_recipients == 0 or num_recipients > 100:
                    return packet[8:]
            except:
                return packet[8:]

            offset, fernet_key = 10, None
            for _ in range(num_recipients):
                key_length = struct.unpack('!H', packet[offset:offset+2])[0]
                offset += 2
                encrypted_key = packet[offset:offset+key_length]
                offset += key_length
                if fernet_key is None:
                    try:
                        fernet_key = self.private_key.decrypt(
                            encrypted_key,
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        )
                    except:
                        pass

            if fernet_key is None:
                raise ValueError("Cannot decrypt key")

            decrypted_data = Fernet(fernet_key).decrypt(packet[offset:])

            ctx = f"  ← {self._raft_context}" if self._raft_context else ""
            hex_fp = packet[:20].hex()
            print(f"RECV {len(packet):>5}B → {len(decrypted_data):>5}B  "
                  f"{Fore.RED}{hex_fp}…{Style.RESET_ALL}{ctx}")
            time.sleep(1) # use time lib to slow the system
            return decrypted_data

        except Exception as e:
            print(f"[ERROR] Decrypt: {e}")
            raise

    def extract_timestamp(self, packet):  # Required by pysyncobj
        return struct.unpack('!Q', packet[:8])[0]
