from colorama import Fore
import json
from cryptography.hazmat.primitives.asymmetric import ec

class ECC_Keys:
    def __init__(self):
        self.private_key = None
    
    def Generate_Private_key(self, curve_name):
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

    def serialize_Private_key(self): 
        return None

    def Load_Private_Key(self):
        return None
    
    def Extract_Public_Key(self):
        return None
    
    def Serialize_Public_key(self):
        return None

    def Load_Public_Key(self):
        return None
