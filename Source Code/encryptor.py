import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import struct

# Use PySyncObj Library
HAS_CRYPTO = True

def getEncryptor(password):

    with open('pki_private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    with open('certificate.pem', 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        public_key = cert.public_key()

    return RSAEncryptor(private_key, public_key)

class RSAEncryptor:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

 # Use Python Cryptography Library (RSA)
    def encrypt_at_time(self, data, timestamp):
        timestamp_bytes = struct.pack('!Q', timestamp)
        encrypted_chunk = self.public_key.encrypt(
            data, # use the data instead of a 'message'
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return timestamp_bytes + encrypted_chunk

 # Use Python Cryptography Library (RSA) 
    def decrypt(self, data):
        encrypted_data = data[8:] 
        plaintext = self.private_key.decrypt(
            encrypted_data, # Change from 'ciphertext' to 'encrypted_data' variable. 
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

# Use PySyncObj Library
    def extract_timestamp(self, data):
        timestamp = struct.unpack('!Q', data[:8])[0]
        return timestamp
