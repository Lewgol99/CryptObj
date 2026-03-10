from colorama import Fore
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class ECC_Keys:
    def __init__(self):
        self.private_key = None
    
    def Generate_Private_key(self, curve_name): # Change this to be specific to ECC in Cryptography Library. 
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
            print(Fore.RED + f'Error: ECC Failed to Generate Curve!')
            return None

    def Serialize_Private_key(self):
        try:
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8, # chnage the format for ECC
                encryption_algorithm=serialization.NoEncryption()
            )
            with open('ecc_private_key.pem', 'wb') as file:
                file.write(pem)
            return True
        except Exception as e:
            print(Fore.RED + 'Error: ECC Private Key Serialization Failure')
            return None 

    def Load_Private_Key(self):
        try:
            with open('ecc_private_key.pem', 'rb') as file:
                self.private_key = serialization.load_pem_private_key(
                    file.read(),
                    password = None
                )
            return self.private_key
        except Exception as e:
            print(Fore.RED + 'Error: Failed to Read ECC Private Key!')
            return None

    def Extract_Public_key(self):
        try:
            if self.private_key is None:
                print(Fore.RED + 'Error: No ECC Private Key Available!')
                return None
            public_key = self.private_key.public_key()
            print(Fore.GREEN + 'Success: ECC Public Key Extracted!')
            return public_key
        except Exception as e:
            print(Fore.RED + 'Error: ECC Public Key Failed to Extract!')
            return None

    def Serialize_Public_key(self):
        try:
            if self.private_key is None:
                print(Fore.RED + 'Error: No ECC Private Key Available!')
                return None
            public_key = self.private_key.public_key()
            pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            with open('ecc_public_key.pem', 'wb') as file:
                file.write(pem)
                print(Fore.GREEN + 'Success: ECC Public Key Serialization!')
                return True
        except Exception as e:
            print(Fore.RED + 'Error: ECC Public Key Serialization Failed!')
            return None

    def Load_Public_Key(self):
        try:
            with open('ecc_public_key.pem', 'rb') as file: 
                self.public_key = serialization.load_pem_public_key(
                    file.read()
                )
                print(Fore.GREEN + 'Success: ECC Public Key Loaded!')
                return self.public_key
        except Exception as e:
            print(Fore.RED + 'Error: Failed to Read ECC Public Key!')
            return None
