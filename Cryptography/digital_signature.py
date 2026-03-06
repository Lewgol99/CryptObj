from colorama import Fore
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes       
from cryptography import x509
from cryptography.hazmat.backends import default_backend     
import json
from asymmetric_keys import Asymmetric_Keys

class DigitalSignature(Asymmetric_Keys): # use asymmetric_keys script for inheritence
    def __init__(self):
        super().__init__() # use for inheritence

    def generate_Private_Key(self, key_size):
        super().Generate_Private_key(key_size)

    def serialize_Private_key(self):
        try:
            pem = self.private_key.private_bytes( # define pem
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
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
        

    def load_public_key_from_cert(self, cert_pem):
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(),
                default_backend()
            )
            return cert.public_key()
        except Exception as e:
            print(Fore.RED + f'Error: Failed to Load Digital Signature Public Key from Certificate!')
            return None


    def serialize_Public_key(self):
        try:
            public_key = self.private_key.public_key()
            pem = public_key.public_bytes(  # define pem
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

    def sign(self, message):
        try:
            signature = self.private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(Fore.GREEN + f'Success: Message Signed!')
            return signature
        except Exception as e:
            print(Fore.RED + f'Error: Failed Signing Message!')
            return None

    def validate(self, public_key, message, signature):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(Fore.GREEN + f'Success: Signature Verified!')
            return True
        except Exception as e:
            print(Fore.RED + f'Error: Signature Failed!')
            return False
