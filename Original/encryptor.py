import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography import x509

def getEncryptor(password):

    with open('pki_private_key.pem', 'rb'): as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    with open('certificate.pem', 'rb'): as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        public_key = cert.public_key()

    return RSAEncryptor(private_key, public_key)

class RSAEncryptor:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def encrypt_at_time(self, data, timestamp):
        pass

    def decrypt(self, data):
        pass
    
    def extract_timestamp(self, data):
        pass
