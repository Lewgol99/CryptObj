import sys
import time 
import json # import to use json data structures
from colorama import Fore, Style # import colorama for colours
from functools import partial
from pysyncobj import SyncObj, replicated, SyncObjConf # import the original pysyncobj system 
import datetime
from pki_setup import PKI # import our setup file
import os
from request import get_ca_status, submit_csr_to_ca # import from our server request file
from encryptor import AsymmetricEncryptor # import from our encryptor file 
from digital_signature import DigitalSignature # import digital signature

if __name__ == '__main__':
    
    with open('nodes.json', 'r') as file: # open our nodes file who will be in the consensus
        nodes = json.load(file)

    with open('asymmetric_ciphers.json', 'r') as file: # open our ciphers file to select an asymmetric cipher
        config = json.load(file)

    with open('rsa_keys.json', 'r') as file:  # open our RSA keys file to load a key
        rsa_keys = json.load(file)

    with open('ecc_curves.json', 'r') as file: # open our ECC Curves to load a curve
        curves = json.load(file)

    with open('ciphers.json', 'r') as file: # open our ciphers file to select a symmetric cipher
        ciphers = json.load(file)

    if len(sys.argv) < 5: # Define 5 system arguements at the terminal command line
        print(Fore.YELLOW + f'Usage: {sys.argv[0]} node_name, asymmetric_cipher, key_size/curve, symmetric_cipher')
        print(Fore.YELLOW + f'Available nodes: {list(nodes.keys())}')
        print(Fore.YELLOW + f'Available asymmetric ciphers: {config["asymmetric_ciphers"]}') # choose RSA or ECC as an arguement
        print(Fore.YELLOW + f'Available key sizes: {rsa_keys["key_sizes"]}')
        print(Fore.YELLOW + f'Available ciphers: {ciphers["ciphers"]}')
        sys.exit(-1)

    node_name = sys.argv[1] # Make the node name arguement 1

    status = get_ca_status()
    print(Fore.YELLOW + f'CA Status: {status}')

    print(Fore.YELLOW + f'Certificate Found — Starting PySyncObj!')
    os.environ['NODE_NAME'] = node_name

    def _set_enc_ctx(label: str):
        try:
            from encryptor import AsymmetricEncryptor
            AsymmetricEncryptor.set_context(label)
        except Exception:
            pass

    class Raft(SyncObj):
        def __init__(self, selfNodeAddr, otherNodeAddrs, nodes_data, node_name):
            print("\n" + "="*60)
            print(f" RAFT NODE  [{node_name}]  starting up")
            print("="*60 + "\n")

            conf = SyncObjConf()
            conf.logCompactionMinEntries = 2
            conf.logCompactionMinTime = 2
            conf.password = "SecureRaft2026"  # triggers pysyncobj to call getEncryptor() from encryptor.py
            conf.node_name = node_name
            super(Raft, self).__init__(selfNodeAddr, otherNodeAddrs, conf)
            self.__counter = 0
            self.nodes_data = nodes_data
            self._last_leader = None

        @replicated
        def incCounter(self):
            _set_enc_ctx("incCounter → replicate")
            self.__counter += 1

        @replicated
        def addValue(self, value, cn):
            _set_enc_ctx(f"addValue({value}) → replicate")
            self.__counter += value

            print(
                f"\n  {'─'*54}\n"
                f"RAFT LOG ENTRY  [{node_name}]  seq={cn}\n"
                f"addValue({value})  |  counter: {self.__counter - value} → "
                f"{Fore.GREEN}{self.__counter}{Style.RESET_ALL}\n"
                f"  {'─'*54}"
            )
            return self.__counter, cn

        def getCounter(self):
            return self.__counter

        def getNodes(self):
            print(self.nodes_data)
            return self.nodes_data

        def _getLeader(self):
            leader = super()._getLeader()
            
            if leader != self._last_leader:
                if leader:
                    try:
                        self_addr = self._selfAddress
                    except AttributeError:
                        self_addr = None
                    is_me = (self_addr is not None and leader == self_addr)
                    role_label = "THIS NODE" if is_me else f"peer  (I am {self_addr or '?'})"
                    print(
                        f"\n  {'='*54}\n"
                        f"RAFT LEADER  →  {leader}  [{role_label}]\n"
                        f"  {'='*54}\n"
                    )
                self._last_leader = leader
            return leader

    def onAdd(res, err, cnt):
        status = Fore.GREEN + "OK" + Style.RESET_ALL if err is None else Fore.RED + str(err) + Style.RESET_ALL
        print(f"onAdd seq={cnt}  result={res}  {status}")

    if node_name not in nodes:
        print(Fore.RED + f'Error: Node {node_name} not found in nodes.json')
        sys.exit(-1)

    self_node = nodes[node_name]
    self_addr = f"{self_node['addr']}:{self_node['port']}"

    partner_addrs = [
        f"{info['addr']}:{info['port']}"
        for name, info in nodes.items() if name != node_name
    ]

    print(f"  self  : {self_addr}")
    print(f"  peers : {partner_addrs}\n")

    asymmetric_cipher = sys.argv[2] # make selecting the asymmetric cipher arguement 2
    if asymmetric_cipher not in config['asymmetric_ciphers']:
        print(Fore.RED + f'Error: {asymmetric_cipher} not found in asymmetric_ciphers.json')
        sys.exit(-1)

    key_param = sys.argv[3]

    if '--tls' in sys.argv:
        tls_index = sys.argv.index('--tls')
        tls_group = sys.argv[tls_index + 1]
        if tls_group not in curves['ec_curves']:
            print(Fore.RED + f'Error: {tls_group} not found in ec_curves.json')
            sys.exit(-1)
        del sys.argv[tls_index:tls_index + 2]
        os.environ['USE_TLS'] = tls_group

        if not os.path.exists('certificate.pem'):
            from request import fetch_root_certificate
            print(Fore.CYAN + 'Fetching CA root certificate for TLS...')
            fetch_root_certificate()

    if asymmetric_cipher == 'RSA':
        key_size = int(key_param)
        if key_size not in rsa_keys['key_sizes']:
            print(Fore.RED + f'Error: Key {key_size} not Found in rsa_keys.json')
            sys.exit(-1)
    elif asymmetric_cipher == 'ECC':
        curve_name = key_param
        if curve_name not in curves['ec_curves']:
            print(Fore.RED + f'Error: Curve {curve_name} not Found in ec_curves.json')
            sys.exit(-1)

    selected_ciphers = sys.argv[4] # make Symmetric Cipher terminal arguement 4
    if selected_ciphers not in ciphers['ciphers']:
        print(Fore.RED + f'Error: Cipher {selected_ciphers} not Found in ciphers.json')
        sys.exit(-1)
    os.environ['SELECTED_CIPHER'] = selected_ciphers 
    AsymmetricEncryptor.set_cipher(selected_ciphers) # call the ciphers

    # For Asymmetric Encryption (RSA or ECC)

    if not os.path.exists('pki_private_key.pem'):
        print(Fore.YELLOW + 'No private key found, generating...')
        if asymmetric_cipher == 'RSA':
            pki = PKI()
            pki.generate_keys(key_size)
            pki.generate_csr(node_name)
            result = submit_csr_to_ca(node_name)
        elif asymmetric_cipher == 'ECC':
            pki = PKI()
            pki.generate_ecc_keys(curve_name)
            pki.generate_csr(node_name)
            result = submit_csr_to_ca(node_name)

    # For Digital Signature (RSA or ECC)

    if not os.path.exists('signing_private_key.pem'):
        print(Fore.YELLOW + 'No signing key found, generating...')
        signer = DigitalSignature()
        if asymmetric_cipher == 'RSA':
            signer.generate_Private_Key(key_size)
        elif asymmetric_cipher == 'ECC':
            signer.generate_Private_Key(curve_name)
        signer.serialize_Private_key()
        signer.serialize_Public_key()
        print(Fore.GREEN + 'Signing keys generated!')

    if not os.path.exists(f'{node_name}_certificate.pem'):
        print(Fore.RED + f'Error: No Certificate Found for {node_name}! Cannot Start PySyncObj!!')
        exit(0)

    o = Raft(self_addr, partner_addrs, nodes, node_name)

    n = 0
    old_value = -1

    while True:
        time.sleep(0.5)

        leader = o._getLeader()

        if leader is not None and n < 20:
            _set_enc_ctx(f"addValue(10) seq={n} → send")
            print(f"  ->  [{node_name}] addValue(10)  seq={n}")
            o.addValue(10, n, callback=partial(onAdd, cnt=n))
            n += 1

        current = o.getCounter()
        if current != old_value:
            old_value = current
            print(f"[{node_name}] counter = {Fore.CYAN}{current}{Style.RESET_ALL}")
