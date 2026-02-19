from colorama import Fore
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json

class Asymmetric_Keys:
    def __init__(self):
        self.private_key = None

    def Generate_Private_key(self, key_size):
        try:
            with open('rsa_keys.json', 'r') as file: # load and read the json array
                config = json.load(file)

            key_sizes = config["key_sizes"] # get the list of RSA key sizes
            print('Available Key Sizes', key_sizes) # show the user the optional RSA key sizes from the array
            if key_size not in key_sizes:
                raise ValueError(Fore.RED + 'Invalid RSA Key Size Selected') # add Value Error for incorrect key selection

            self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size, # take the key size from the user input
            )
            print(Fore.GREEN + 'Success: PKI Private Key Generation')
            return self.private_key
        except Exception as e:
            print(Fore.RED + 'Error: Failed to Generate PKI Private Key!')
            return None
            
    def Serialize_Private_key(self):
        try:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open('pki_private_key.pem', 'wb') as file:
                file.write(pem)
            return True
        except Exception as e:
            print(Fore.RED + 'Error: PKI Private Key Serialization Failure')
            return None 

    def Load_Private_Key(self):
        try:
            with open('pki_private_key.pem', 'rb') as file:
                self.private_key = serialization.load_pem_private_key(
                    file.read(),
                    password = None
                )
            return self.private_key
        except Exception as e:
            print(Fore.RED + 'Error: Failed to Read PKI Private Key!')
            return None

    def Extract_Public_key(self):
        try:
            if self.private_key is None:
                print(Fore.RED + 'Error: No PKI Private Key Available!')
                return None
            public_key = self.private_key.public_key()
            print(Fore.GREEN + 'Success: PKI Public Key Extracted!')
            return public_key
        except Exception as e:
            print(Fore.RED + 'Error: PKI Public Key Failed to Extract!')
            return None

    def Serialize_Public_key(self):
        try:
            if self.private_key is None:
                print(Fore.RED + 'Error: No PKI Private Key Available!')
                return None
            public_key = self.private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            with open('pki_public_key.pem', 'wb') as file:
                file.write(pem)
                print(Fore.GREEN + 'Success: PKI Public Key Serialization!')
                return True
        except Exception as e:
            print(Fore.RED + 'Error: PKI Public Key Serialization Failed!')
            return None

    def Load_Public_Key(self):
        try:
            with open('pki_public_key.pem', 'rb') as file: 
                self.public_key = serialization.load_pem_public_key(
                    file.read()
                )
                print(Fore.GREEN + 'Success: PKI Public Key Loaded!')
                return self.public_key
        except Exception as e:
            print(Fore.RED + 'Error: Failed to Read PKI Public Key!')
            return None
