"""
ANNOTATED ENCRYPTOR.PY - Showing Exactly Where Everything Comes From
"""

# ============================================================================
# IMPORTS - Where each import comes from
# ============================================================================

# From cryptography.fernet module
# Documentation: https://cryptography.io/en/latest/fernet/
# What it does: Symmetric encryption (AES-128-CBC + HMAC-SHA256)
from cryptography.fernet import Fernet

# From cryptography.hazmat.primitives.asymmetric module
# Documentation: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/padding/
# What it does: Provides OAEP padding for RSA encryption
from cryptography.hazmat.primitives.asymmetric import padding

# From cryptography.hazmat.primitives module
# Documentation: https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
# What it does: Provides hash algorithms (SHA256, SHA384, SHA512, etc.)
from cryptography.hazmat.primitives import hashes, serialization

# From cryptography.hazmat.backends module
# Documentation: https://cryptography.io/en/latest/hazmat/backends/
# What it does: Provides the backend for cryptographic operations
from cryptography.hazmat.backends import default_backend

# From cryptography.x509 module
# Documentation: https://cryptography.io/en/latest/x509/
# What it does: X.509 certificate parsing and creation
from cryptography import x509

# Third-party library for colored console output (NOT from cryptography)
from colorama import Fore, Style, init

# Python standard library modules (NOT from cryptography)
import struct  # Binary data packing/unpacking
import os      # Operating system interface
import glob    # File pattern matching
import time    # Time-related functions

init(autoreset=True)  # Initialize colorama

# Flag to indicate if cryptography library is available
HAS_CRYPTO = True


# ============================================================================
# HELPER FUNCTION
# ============================================================================

def _display(data, n=100):
    """
    Helper function to display data (from pysyncobj pattern)
    Uses pickle and zlib (standard library, NOT from cryptography)
    """
    try:
        import pickle, zlib
        s = str(pickle.loads(zlib.decompress(data)))
        return s if len(s) <= n else s[:n] + '...'
    except:
        return str(data[:80] if len(data) <= 80 else data[:80] + b'...')


# ============================================================================
# MAIN FUNCTION - Interface from PySyncObj
# ============================================================================

def getEncryptor(password):
    """
    Main entry point called by pysyncobj
    
    FROM: PySyncObj pattern (original used this for password-based encryption)
    YOU CHANGED: Now loads PKI keys instead of using password
    """
    
    # Python standard library (NOT from cryptography)
    node = os.environ.get('NODE_NAME')
    base = os.getcwd()
    cert_dir = os.path.join(base, node) if os.path.exists(os.path.join(base, node)) else base
    
    # ========================================================================
    # LOADING PRIVATE KEY
    # ========================================================================
    
    key_path = os.path.join(cert_dir, 'pki_private_key.pem')
    if not os.path.exists(key_path):
        key_path = os.path.join(base, 'pki_private_key.pem')
    
    with open(key_path, 'rb') as f:
        # FROM: cryptography.hazmat.primitives.serialization
        # FUNCTION: load_pem_private_key()
        # DOCS: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
        # WHAT: Loads an RSA private key from PEM format
        priv = serialization.load_pem_private_key(
            f.read(), 
            password=None,  # No password protection on the key file
            backend=default_backend()  # FROM: cryptography.hazmat.backends
        )
    
    # ========================================================================
    # LOADING PUBLIC KEYS FROM CERTIFICATES
    # ========================================================================
    
    # Find all certificate files using glob (standard library)
    certs = list(set(
        glob.glob(os.path.join(cert_dir, '*_certificate.pem')) + 
        glob.glob(os.path.join(base, '*_certificate.pem'))
    ))
    
    pubs = {}  # Dictionary to store public keys
    
    for cf in certs:
        try:
            with open(cf, 'rb') as f:
                # FROM: cryptography.x509
                # FUNCTION: load_pem_x509_certificate()
                # DOCS: https://cryptography.io/en/latest/x509/reference/
                # WHAT: Loads an X.509 certificate from PEM format
                # RETURNS: A Certificate object
                cert = x509.load_pem_x509_certificate(
                    f.read(), 
                    default_backend()
                )
                
                # FROM: Certificate.public_key() method
                # DOCS: https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.public_key
                # WHAT: Extracts the public key from the certificate
                # RETURNS: RSAPublicKey (or other key type)
                public_key = cert.public_key()
                
                # Store in dictionary with node name as key
                name = os.path.basename(cf).replace('_certificate.pem', '')
                pubs[name] = public_key
        except:
            pass
    
    print(f"[{node}] {len(pubs)} RSA certs, encrypt={'ON' if len(pubs)>=2 else 'OFF'}")
    
    # Return our custom encryptor class
    return RSAEncryptor(priv, pubs, node, cert_dir, base)


# ============================================================================
# RSA ENCRYPTOR CLASS
# ============================================================================

class RSAEncryptor:
    """
    Custom encryptor class using hybrid encryption
    
    FROM: YOUR IMPLEMENTATION (not from cryptography or pysyncobj)
    USES: cryptography library components for the actual encryption
    """
    
    def __init__(self, priv, pubs, node, cert_dir, base):
        """
        Initialize the encryptor
        
        Args:
            priv: RSA private key (from serialization.load_pem_private_key)
            pubs: Dictionary of RSA public keys (from cert.public_key())
            node: Node name (string)
            cert_dir: Certificate directory path (string)
            base: Base directory path (string)
        """
        self.priv = priv          # RSA private key object
        self.pubs = pubs          # Dict of RSA public key objects
        self.node = node          # Node identifier
        self.cert_dir = cert_dir  # Where to find certificates
        self.base = base          # Base directory
        self.last_check = 0       # Timestamp of last certificate check
        self.enabled = len(pubs) >= 2  # Need at least 2 keys for encryption
    
    def _load_certificates(self):
        """
        Dynamically reload certificates from filesystem
        
        FROM: YOUR IMPLEMENTATION
        USES: cryptography.x509 for certificate parsing
        """
        # Rate limiting: don't check more than once per 5 seconds
        if time.time() - self.last_check < 5:
            return
        
        self.last_check = time.time()
        
        # Scan for certificate files
        for d in [self.cert_dir, self.base]:
            for cf in glob.glob(os.path.join(d, '*_certificate.pem')):
                name = os.path.basename(cf).replace('_certificate.pem', '')
                
                if name not in self.pubs:
                    try:
                        with open(cf, 'rb') as f:
                            # FROM: cryptography.x509.load_pem_x509_certificate()
                            cert = x509.load_pem_x509_certificate(
                                f.read(), 
                                default_backend()
                            )
                            
                            # FROM: Certificate.public_key()
                            pub = cert.public_key()
                            
                            # FROM: cryptography.hazmat.primitives.asymmetric.rsa
                            # DOCS: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
                            from cryptography.hazmat.primitives.asymmetric import rsa
                            
                            # TYPE CHECK: Only accept RSA keys
                            # FROM: isinstance() check with rsa.RSAPublicKey
                            if isinstance(pub, rsa.RSAPublicKey):
                                self.pubs[name] = pub
                            else:
                                print(f"[SKIP] {name}: Not RSA cert ({type(pub).__name__})")
                    except:
                        pass
        
        # Update encryption enabled flag
        if len(self.pubs) >= 2 and not self.enabled:
            self.enabled = True
    
    def encrypt_at_time(self, data, ts):
        """
        Encrypt data with timestamp using hybrid encryption
        
        Args:
            data: bytes to encrypt
            ts: timestamp (integer)
        
        Returns:
            bytes: encrypted packet
        
        FROM: YOUR IMPLEMENTATION
        USES: Multiple cryptography library components
        """
        try:
            print(f"\n[SEND] {len(data)}B")
            print(f"   {Fore.MAGENTA}{_display(data)}{Style.RESET_ALL}")
            
            self._load_certificates()
            
            # If not enough keys, return unencrypted (with timestamp)
            if not self.enabled:
                # FROM: struct.pack (Python standard library)
                # FORMAT: '!Q' = network byte order (big-endian), unsigned long long (8 bytes)
                return struct.pack('!Q', ts) + data
            
            # ================================================================
            # LAYER 1: FERNET ENCRYPTION (SYMMETRIC)
            # ================================================================
            
            # FROM: cryptography.fernet.Fernet.generate_key()
            # DOCS: https://cryptography.io/en/latest/fernet/
            # WHAT: Generates a random 32-byte Fernet key
            # RETURNS: bytes (base64-encoded key)
            fk = Fernet.generate_key()
            
            # FROM: cryptography.fernet.Fernet(key).encrypt(data)
            # WHAT: Encrypts data using AES-128-CBC + HMAC-SHA256
            # RETURNS: bytes (encrypted data with authentication)
            fe = Fernet(fk).encrypt(data)
            
            # ================================================================
            # LAYER 2: RSA ENCRYPTION (ASYMMETRIC)
            # ================================================================
            
            # Build packet header
            # FROM: struct.pack (Python standard library)
            result = struct.pack('!Q', ts)  # Timestamp (8 bytes)
            result += struct.pack('!H', len(self.pubs))  # Number of keys (2 bytes)
            
            # Encrypt the Fernet key for each recipient
            for pub in self.pubs.values():
                # FROM: RSAPublicKey.encrypt()
                # DOCS: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.encrypt
                # ARGS:
                #   - plaintext: The Fernet key (32 bytes)
                #   - padding: OAEP padding configuration
                ek = pub.encrypt(
                    fk,  # The Fernet key to encrypt
                    
                    # FROM: cryptography.hazmat.primitives.asymmetric.padding.OAEP
                    # DOCS: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/padding/#cryptography.hazmat.primitives.asymmetric.padding.OAEP
                    # WHAT: Optimal Asymmetric Encryption Padding (secure RSA padding)
                    padding.OAEP(
                        # MGF (Mask Generation Function)
                        # FROM: padding.MGF1
                        # DOCS: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/padding/#cryptography.hazmat.primitives.asymmetric.padding.MGF1
                        mgf=padding.MGF1(
                            algorithm=hashes.SHA256()  # FROM: cryptography.hazmat.primitives.hashes
                        ),
                        
                        # Hash algorithm for OAEP
                        # FROM: cryptography.hazmat.primitives.hashes.SHA256
                        # DOCS: https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
                        algorithm=hashes.SHA256(),
                        
                        # Label (usually None)
                        label=None
                    )
                )
                
                # Add encrypted key to packet
                # Format: [2 bytes: key length][encrypted key]
                result += struct.pack('!H', len(ek))  # Key length
                result += ek  # Encrypted Fernet key
            
            # Append the Fernet-encrypted data
            result += fe
            
            print(f"🔒 {Fore.RED}{result[:40].hex()}...{Style.RESET_ALL} ({len(result)}B)\n")
            return result
            
        except Exception as e:
            print(f"[ERROR] Encrypt: {e}")
            raise
    
    def decrypt(self, data):
        """
        Decrypt a hybrid-encrypted packet
        
        Args:
            data: bytes from encrypt_at_time()
        
        Returns:
            bytes: decrypted plaintext
        
        FROM: YOUR IMPLEMENTATION
        USES: Multiple cryptography library components
        """
        try:
            self._load_certificates()
            
            # Sanity check
            if len(data) < 14:
                return data[8:]  # Return without timestamp
            
            try:
                # FROM: struct.unpack (Python standard library)
                # Read number of encrypted keys from packet
                pc = struct.unpack('!H', data[8:10])[0]
                
                # Sanity check: valid number of keys?
                if pc == 0 or pc > 100:
                    return data[8:]  # Not encrypted
            except:
                return data[8:]
            
            print(f"\n[RECV] {len(data)}B")
            print(f"   {Fore.RED}{data[:40].hex()}...{Style.RESET_ALL}")
            
            # ================================================================
            # EXTRACT AND DECRYPT FERNET KEY
            # ================================================================
            
            offset = 10  # Start after timestamp (8) + key count (2)
            fk = None    # Will hold the decrypted Fernet key
            
            # Try each encrypted key until we find one we can decrypt
            for _ in range(pc):
                # Read encrypted key length
                kl = struct.unpack('!H', data[offset:offset+2])[0]
                offset += 2
                
                # Read encrypted key
                ek = data[offset:offset+kl]
                offset += kl
                
                # Try to decrypt with our private key
                if not fk:
                    try:
                        # FROM: RSAPrivateKey.decrypt()
                        # DOCS: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.decrypt
                        # WHAT: Decrypts data that was encrypted with the public key
                        # RETURNS: bytes (the Fernet key)
                        fk = self.priv.decrypt(
                            ek,  # Encrypted Fernet key
                            
                            # FROM: padding.OAEP (same as encryption)
                            # MUST use SAME padding parameters as encryption
                            padding.OAEP(
                                mgf=padding.MGF1(
                                    algorithm=hashes.SHA256()
                                ),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                    except:
                        pass  # This key wasn't for us, try next one
            
            # Check if we successfully decrypted a Fernet key
            if not fk:
                raise ValueError("Cannot decrypt key")
            
            # ================================================================
            # DECRYPT DATA WITH FERNET
            # ================================================================
            
            # FROM: Fernet(key).decrypt(data)
            # DOCS: https://cryptography.io/en/latest/fernet/
            # WHAT: Decrypts data using the Fernet key
            # RETURNS: bytes (original plaintext)
            pt = Fernet(fk).decrypt(data[offset:])
            
            print(f"   {Fore.MAGENTA}{_display(pt)}{Style.RESET_ALL} ({len(pt)}B)\n")
            return pt
            
        except Exception as e:
            print(f"[ERROR] Decrypt: {e}")
            raise
    
    def extract_timestamp(self, data):
        """
        Extract timestamp from encrypted packet
        
        FROM: YOUR IMPLEMENTATION (pysyncobj pattern)
        USES: struct.unpack (Python standard library)
        """
        # FROM: struct.unpack
        # FORMAT: '!Q' = network byte order, unsigned long long (8 bytes)
        return struct.unpack('!Q', data[:8])[0]


# ============================================================================
# SUMMARY: WHERE EACH PIECE COMES FROM
# ============================================================================

"""
FROM PYSYNCOBJ ORIGINAL:
├─ getEncryptor() function interface
├─ HAS_CRYPTO flag pattern
├─ _display() helper pattern
└─ Integration expectations (encrypt/decrypt methods)

FROM CRYPTOGRAPHY LIBRARY:
├─ cryptography.fernet.Fernet
│  ├─ Fernet.generate_key() - Generate random symmetric key
│  ├─ Fernet(key).encrypt(data) - Symmetric encryption
│  └─ Fernet(key).decrypt(data) - Symmetric decryption
│
├─ cryptography.hazmat.primitives.asymmetric.rsa
│  ├─ RSAPublicKey - Public key type
│  └─ RSAPrivateKey - Private key type
│
├─ cryptography.hazmat.primitives.asymmetric.padding
│  ├─ OAEP - Secure RSA padding
│  └─ MGF1 - Mask generation function
│
├─ cryptography.hazmat.primitives.hashes
│  └─ SHA256 - Hash algorithm
│
├─ cryptography.hazmat.primitives.serialization
│  └─ load_pem_private_key() - Load RSA private key from file
│
├─ cryptography.x509
│  ├─ load_pem_x509_certificate() - Load certificate from file
│  └─ Certificate.public_key() - Extract public key from cert
│
└─ cryptography.hazmat.backends
   └─ default_backend() - Cryptographic backend

FROM PYTHON STANDARD LIBRARY:
├─ struct - Binary data packing/unpacking
├─ os - File system operations
├─ glob - File pattern matching
├─ time - Timestamp operations
├─ pickle - Object serialization (in _display)
└─ zlib - Compression (in _display)

FROM THIRD-PARTY (colorama):
└─ Fore, Style - Colored console output

YOUR CUSTOM IMPLEMENTATION:
├─ RSAEncryptor class structure
├─ Hybrid encryption logic (Fernet + RSA)
├─ Multi-recipient packet format
├─ Dynamic certificate loading
├─ Certificate type validation
└─ Packet structure design
"""
