"""RSA Hybrid Encryptor: Fernet + RSA"""
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from colorama import Fore, Style, init
import struct, os, glob, time

init(autoreset=True)
HAS_CRYPTO = True

def _display(data, n=100):
    try:
        import pickle, zlib
        s = str(pickle.loads(zlib.decompress(data)))
        return s if len(s) <= n else s[:n] + '...'
    except:
        return str(data[:80] if len(data) <= 80 else data[:80] + b'...')

def getEncryptor(password):
    node = os.environ.get('NODE_NAME')
    base = os.getcwd()
    cert_dir = os.path.join(base, node) if os.path.exists(os.path.join(base, node)) else base
    
    # Load private key
    key_path = os.path.join(cert_dir, 'pki_private_key.pem')
    if not os.path.exists(key_path):
        key_path = os.path.join(base, 'pki_private_key.pem')
    
    with open(key_path, 'rb') as f:
        priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    # Load public keys
    certs = list(set(glob.glob(os.path.join(cert_dir, '*_certificate.pem')) + 
                     glob.glob(os.path.join(base, '*_certificate.pem'))))
    pubs = {}
    for cf in certs:
        try:
            with open(cf, 'rb') as f:
                pubs[os.path.basename(cf).replace('_certificate.pem', '')] = \
                    x509.load_pem_x509_certificate(f.read(), default_backend()).public_key()
        except:
            pass
    
    print(f"🔐 {node}: {len(pubs)} RSA certs, encrypt={'ON' if len(pubs)>=2 else 'OFF'}")
    return RSAEncryptor(priv, pubs, node, cert_dir, base)

class RSAEncryptor:
    def __init__(self, priv, pubs, node, cert_dir, base):
        self.priv, self.pubs, self.node = priv, pubs, node
        self.cert_dir, self.base = cert_dir, base
        self.last_check = 0
        self.enabled = len(pubs) >= 2
    
    def _load_certificates(self):
        if time.time() - self.last_check < 5:
            return
        self.last_check = time.time()
        for d in [self.cert_dir, self.base]:
            for cf in glob.glob(os.path.join(d, '*_certificate.pem')):
                name = os.path.basename(cf).replace('_certificate.pem', '')
                if name not in self.pubs:
                    try:
                        with open(cf, 'rb') as f:
                            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                            pub = cert.public_key()
                            # Import RSA types
                            from cryptography.hazmat.primitives.asymmetric import rsa
                            # ONLY accept RSA keys
                            if isinstance(pub, rsa.RSAPublicKey):
                                self.pubs[name] = pub
                            else:
                                print(f"⚠️  Skipping {name}: Not an RSA certificate (found {type(pub).__name__})")
                    except:
                        pass
        if len(self.pubs) >= 2 and not self.enabled:
            self.enabled = True
    
    def encrypt_at_time(self, data, ts):
        try:
            print(f"\n📤 SEND: {len(data)}B")
            print(f"   {Fore.MAGENTA}{_display(data)}{Style.RESET_ALL}")
            
            self._load_certificates()
            if not self.enabled:
                return struct.pack('!Q', ts) + data
            
            # LAYER 1: Fernet
            fk = Fernet.generate_key()
            fe = Fernet(fk).encrypt(data)
            
            # LAYER 2: RSA
            result = struct.pack('!Q', ts) + struct.pack('!H', len(self.pubs))
            for pub in self.pubs.values():
                ek = pub.encrypt(fk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), 
                                                   algorithm=hashes.SHA256(), label=None))
                result += struct.pack('!H', len(ek)) + ek
            result += fe
            
            print(f"   ✅ {len(result)}B total")
            print(f"🔒 {Fore.RED}{result[:40].hex()}...{Style.RESET_ALL}\n")
            return result
        except Exception as e:
            print(f"❌ ENCRYPT ERROR: {e}")
            raise
    
    def decrypt(self, data):
        try:
            self._load_certificates()
            if len(data) < 14:
                return data[8:]
            
            try:
                pc = struct.unpack('!H', data[8:10])[0]
                if pc == 0 or pc > 100:
                    return data[8:]
            except:
                return data[8:]
            
            print(f"\n📥 RECV: {len(data)}B")
            print(f"   {Fore.RED}{data[:40].hex()}...{Style.RESET_ALL}")
            
            # Extract and decrypt Fernet key
            offset, fk = 10, None
            for _ in range(pc):
                kl = struct.unpack('!H', data[offset:offset+2])[0]
                offset += 2
                ek = data[offset:offset+kl]
                offset += kl
                if not fk:
                    try:
                        fk = self.priv.decrypt(ek, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), 
                                                                 algorithm=hashes.SHA256(), label=None))
                    except:
                        pass
            
            if not fk:
                raise ValueError("Cannot decrypt key")
            
            # Decrypt data
            pt = Fernet(fk).decrypt(data[offset:])
            print(f"   ✅ {len(pt)}B plain")
            print(f"📜 {Fore.MAGENTA}{_display(pt)}{Style.RESET_ALL}\n")
            return pt
        except Exception as e:
            print(f"❌ DECRYPT ERROR: {e}")
            raise
    
    def extract_timestamp(self, data):
        return struct.unpack('!Q', data[:8])[0]
