from colorama import Fore
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class ECC_Keys:
    def __init__(self):
        self.private_key = None

    def Generate_Private_Key(self, curve_name):
        try:
            with open('ecc_curves.json', 'r') as file:
                config = json.load(file)
            ec_curves = config["ec_curves"]
            print('Available Curves', ec_curves)
            if curve_name not in ec_curves:
                raise ValueError(Fore.RED + f'Invalid ECC Curves Selected!')
            curve_obj = getattr(ec, curve_name)()
            self.private_key = ec.generate_private_key(curve_obj)
            print(Fore.GREEN + f'Success: ECC Curve Generation!')
            return self.private_key
        except Exception as e:
            print(Fore.RED + f'Error: ECC Failed to Generate Curve! {e}')
            return None

    def Serialize_Private_Key(self):
        try:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open('pki_private_key.pem', 'wb') as file:
                file.write(pem)
            return True
        except Exception as e:
            print(Fore.RED + f'Error: ECC Private Key Serialization Failure {e}')
            return None

    def Load_Private_Key(self):
        try:
            with open('pki_private_key.pem', 'rb') as file:
                self.private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=None
                )
            return self.private_key
        except Exception as e:
            print(Fore.RED + f'Error: Failed to Read ECC Private Key! {e}')
            return None

    def Extract_Public_Key(self):
        try:
            if self.private_key is None:
                print(Fore.RED + 'Error: No ECC Private Key Available!')
                return None
            public_key = self.private_key.public_key()
            print(Fore.GREEN + 'Success: ECC Public Key Extracted!')
            return public_key
        except Exception as e:
            print(Fore.RED + f'Error: ECC Public Key Failed to Extract! {e}')
            return None

    def Serialize_Public_Key(self):
        try:
            if self.private_key is None:
                print(Fore.RED + 'Error: No ECC Private Key Available!')
                return None
            public_key = self.private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open('pki_public_key.pem', 'wb') as file:
                file.write(pem)
            print(Fore.GREEN + 'Success: ECC Public Key Serialization!')
            return True
        except Exception as e:
            print(Fore.RED + f'Error: ECC Public Key Serialization Failed! {e}')
            return None

    def Load_Public_Key(self):
        try:
            with open('pki_public_key.pem', 'rb') as file:
                self.public_key = serialization.load_pem_public_key(
                    file.read()
                )
            print(Fore.GREEN + 'Success: ECC Public Key Loaded!')
            return self.public_key
        except Exception as e:
            print(Fore.RED + f'Error: Failed to Read ECC Public Key! {e}')
            return None
