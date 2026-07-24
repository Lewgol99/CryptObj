from colorama import Fore
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from asymmetric_keys import Asymmetric_Keys

class CertificateSigningRequest:
    def __init__(self, private_key):
        self.private_key = private_key
        self.csr = None

    def Create_CSR(self, node_name):
        try:
            self.csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "UK"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "dollar"),
                x509.NameAttribute(NameOID.COMMON_NAME, node_name),
            ])).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(node_name)]),
                critical=False,
            ).sign(self.private_key, hashes.SHA256())
            print(Fore.GREEN + 'Success: CSR Successfully Performed!')  
            return self.csr 
        except Exception as e:
            print(Fore.RED + f'Error: CSR Failed to Perform {e}')
            return None

    def Save_CSR(self, filename='csr.pem'):
        if self.csr is None:
            print(Fore.RED + f'Error: No CSR Generated! {e}')
            return None
        try:
            with open(filename, "wb") as f: 
                f.write(self.csr.public_bytes(serialization.Encoding.PEM))
            print(Fore.GREEN + 'Success: CSR Write!')
            return filename
        except Exception as e:
            print(Fore.RED + f'Error: CSR Failed to Write! {e}')
            return None
