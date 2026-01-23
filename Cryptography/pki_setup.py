from asymmetric_keys import Asymmetric_Keys
from csr import CertificateSigningRequest
from colorama import Fore

class PKI:
    def __init__(self):
        self.keygen = None
        self.private_key = None 

    def generate_keys(self):
        self.keygen = Asymmetric_Keys()
        self.keygen.Generate_Private_key()
        self.keygen.Serialize_Private_key()
        self.private_key = self.keygen.private_key
        
    def generate_csr(self):
        if self.private_key is None:
            print(Fore.RED + f'Error: Generate Keys First!')
            return None
        csr = CertificateSigningRequest(self.private_key)
        csr.Create_CSR()
        csr.Save_CSR()
