from asymmetric_keys import Asymmetric_Keys
from ecc_keys import ECC_Keys
from csr import CertificateSigningRequest
from cryptography.hazmat.primitives import serialization
from colorama import Fore

class PKI:
    def __init__(self):
        self.keygen = None
        self.private_key = None

    def generate_keys(self, key_size):
        self.keygen = Asymmetric_Keys()
        self.keygen.Generate_Private_key(key_size)
        self.keygen.Serialize_Private_key()
        self.private_key = self.keygen.private_key

    def generate_ecc_keys(self, curve_name):
        self.keygen = ECC_Keys()
        self.keygen.Generate_Private_Key(curve_name)
        self.keygen.Serialize_Private_Key()
        self.private_key = self.keygen.private_key
        self.keygen.Serialize_Public_Key()

    def generate_csr(self, node_name):
        if self.private_key is None:
            print(Fore.RED + 'Error: Generate Keys First!')
            return None
        csr = CertificateSigningRequest(self.private_key)
        csr.Create_CSR(node_name)
        csr.Save_CSR()
