from colorama import Fore
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes       
from cryptography import x509
from cryptography.hazmat.backends import default_backend     
import json
from asymmetric_keys import Asymmetric_Keys
from ecc_keys import ECC_Keys
from ds_latency_monitor import DSLatencyMonitor
from ds_throughput_monitor import DSThroughputMonitor

class DigitalSignature(Asymmetric_Keys):
    def __init__(self):
        self.latency_monitor = DSLatencyMonitor()
        self.throughput_monitor = DSThroughputMonitor()
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

    def sign(self, message, sender_ip, recipient_ip): # include IP addreses 
        try:
            self.throughput_monitor.start_throughput()
            self.latency_monitor.start_latency()
            message = (','.join([sender_ip] + recipiant_ips + '||').encode() + message # include IP adrdress
            if isinstance(self.private_key, rsa.RSAPrivateKey):
                signature = self.private_key.sign(
                    message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            else:
                signature = self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))
            self.throughput_monitor.stop_throughput(len(message), 'sign')
            self.latency_monitor.stop_latency('sign')
            print(Fore.GREEN + f'Success: Message Signed!')
            return signature, message # return digital signature and IP address
        except Exception as e:
            print(Fore.RED + f'Error: Failed Signing Message! {e}')
            return None

    def validate(self, public_key, message, signature):
        try:
            self.throughput_monitor.start_throughput()
            self.latency_monitor.start_latency()
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    signature, message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            else:
                public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            self.throughput_monitor.stop_throughput(len(message), 'verify')
            self.latency_monitor.stop_latency('verify')
            print(Fore.GREEN + f'Success: Signature Verified!')
            return True
        except Exception as e:
            print(Fore.RED + f'Error: Signature Failed!')
            return False
