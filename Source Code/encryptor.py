import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct
import os
import glob
import traceback
import time

# Use PySyncObj Library
HAS_CRYPTO = True

def getEncryptor(password):
    # Get node name from environment
    node_name = os.environ.get('NODE_NAME')
    
    # Try node-specific directory first (matching transport.py logic)
    base_dir = os.getcwd()
    node_specific_dir = os.path.join(base_dir, node_name)
    
    # Check which directory has the certificates
    if os.path.exists(node_specific_dir):
        cert_dir = node_specific_dir
    else:
        cert_dir = base_dir
    
    print(f"🔍 Initializing encryptor for node: {node_name}")
    print(f"🔍 Looking in directory: {cert_dir}")
    
    # Load THIS node's private key
    private_key_path = os.path.join(cert_dir, 'pki_private_key.pem')
    
    if not os.path.exists(private_key_path):
        # Try in base directory as fallback
        private_key_path = os.path.join(base_dir, 'pki_private_key.pem')
    
    print(f"🔍 Private key path: {private_key_path}")
    
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    print(f"✅ Loaded private key from: {private_key_path}")
    
    # LOAD ALL CERTIFICATES IMMEDIATELY - don't wait
    cert_files = glob.glob(os.path.join(cert_dir, '*_certificate.pem'))
    cert_files.extend(glob.glob(os.path.join(base_dir, '*_certificate.pem')))
    cert_files = list(set(cert_files))  # Remove duplicates
    
    public_keys = {}
    for cert_file in cert_files:
        cert_node_name = os.path.basename(cert_file).replace('_certificate.pem', '')
        try:
            with open(cert_file, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                public_keys[cert_node_name] = cert.public_key()
            print(f"✅ Loaded public key for: {cert_node_name}")
        except Exception as e:
            print(f"❌ Failed to load cert {cert_file}: {e}")
    
    print(f"📊 Total public keys loaded at startup: {len(public_keys)}")
    
    return RSAEncryptor(private_key, public_keys, node_name, cert_dir, base_dir)

class RSAEncryptor:
    def __init__(self, private_key, public_keys, node_name, cert_dir, base_dir):
        self.private_key = private_key
        self.public_keys = public_keys
        self.node_name = node_name
        self.cert_dir = cert_dir
        self.base_dir = base_dir
        self.last_cert_check = 0
        
        # Enable encryption immediately if we have certs
        self.encryption_enabled = len(public_keys) >= 2
        
        if self.encryption_enabled:
            print(f"🔐 ENCRYPTION ENABLED at startup - {len(public_keys)} certificates loaded")
        else:
            print(f"⚠️  ENCRYPTION DISABLED - only {len(public_keys)} certificate(s) loaded, need at least 2")
    
    def _load_certificates(self):
        """Reload certificates from disk - called periodically to pick up new certs"""
        current_time = time.time()
        
        # Only check for new certificates every 2 seconds
        if current_time - self.last_cert_check < 2:
            return
        
        self.last_cert_check = current_time
        
        # Check both directories for certificates
        cert_files = glob.glob(os.path.join(self.cert_dir, '*_certificate.pem'))
        cert_files.extend(glob.glob(os.path.join(self.base_dir, '*_certificate.pem')))
        
        # Remove duplicates
        cert_files = list(set(cert_files))
        
        old_count = len(self.public_keys)
        
        for cert_file in cert_files:
            cert_node_name = os.path.basename(cert_file).replace('_certificate.pem', '')
            
            # Skip if already loaded
            if cert_node_name in self.public_keys:
                continue
            
            try:
                with open(cert_file, 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    self.public_keys[cert_node_name] = cert.public_key()
                print(f"✅ Dynamically loaded public key for: {cert_node_name} (total: {len(self.public_keys)})")
            except Exception as e:
                print(f"❌ Failed to load cert {cert_file}: {e}")
        
        # Enable encryption once we have at least 2 certificates (self + at least one peer)
        if len(self.public_keys) >= 2 and not self.encryption_enabled:
            self.encryption_enabled = True
            print(f"🔐 ENCRYPTION ENABLED - {len(self.public_keys)} certificates now loaded")
        
        # Show status if certificates changed
        if len(self.public_keys) != old_count:
            print(f"📊 Certificate status: {len(self.public_keys)} certs, encryption={'ON' if self.encryption_enabled else 'OFF'}")

    def encrypt_at_time(self, data, timestamp):
        """
        Hybrid encryption approach - ALWAYS ENCRYPT if we have peer certificates
        """
        try:
            # Check for new certificates
            self._load_certificates()
            
            # If still no encryption, use passthrough
            if not self.encryption_enabled:
                print(f"⚠️  PASSTHROUGH: only {len(self.public_keys)} cert(s), need 2+")
                timestamp_bytes = struct.pack('!Q', timestamp)
                return timestamp_bytes + data
            
            print(f"🔐 ENCRYPTING {len(data)} bytes for {len(self.public_keys)} peers")
            
            timestamp_bytes = struct.pack('!Q', timestamp)
            
            # Generate random AES key (32 bytes = 256 bits)
            aes_key = os.urandom(32)
            iv = os.urandom(16)
            
            # Encrypt data with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            
            # Encrypt AES key for each peer using their public key
            encrypted_keys = []
            peer_count = len(self.public_keys)
            
            for peer_name, public_key in self.public_keys.items():
                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_keys.append(encrypted_aes_key)
            
            # Package format:
            # [timestamp:8][peer_count:2][key1_len:2][key1][key2_len:2][key2]...[iv:16][encrypted_data]
            result = timestamp_bytes
            result += struct.pack('!H', peer_count)
            
            for enc_key in encrypted_keys:
                result += struct.pack('!H', len(enc_key))
                result += enc_key
            
            result += iv
            result += encrypted_data
            
            print(f"🔐 ENCRYPTED SUCCESS: {len(result)} bytes (was {len(data)} bytes plaintext)")
            return result
            
        except Exception as e:
            print(f"❌ ENCRYPTION FAILED: {e}")
            traceback.print_exc()
            raise

    def decrypt(self, data):
        """
        Decrypt using THIS node's private key - or passthrough if encryption not enabled
        """
        try:
            # Check for new certificates
            self._load_certificates()
            
            # Check if this is encrypted data or passthrough data
            if len(data) < 12:
                # Too short to be encrypted, must be passthrough
                print(f"🔓 PASSTHROUGH (too short): {len(data)} bytes")
                return data[8:]  # Skip timestamp
            
            offset = 8  # Skip timestamp
            
            # Try to read peer count - if this fails, it's passthrough data
            try:
                peer_count = struct.unpack('!H', data[offset:offset+2])[0]
                
                # Sanity check: peer_count should be reasonable (1-100)
                if peer_count == 0 or peer_count > 100:
                    # Probably not encrypted data
                    print(f"🔓 PASSTHROUGH (invalid peer_count={peer_count}): {len(data)} bytes")
                    return data[8:]  # Skip timestamp
                    
            except:
                # Not encrypted
                print(f"🔓 PASSTHROUGH (parse error): {len(data)} bytes")
                return data[8:]
            
            print(f"🔓 DECRYPTING {len(data)} bytes (peer_count={peer_count})")
            offset += 2
            
            # Extract all encrypted AES keys
            encrypted_keys = []
            for i in range(peer_count):
                if offset + 2 > len(data):
                    raise ValueError(f"Not enough data for key {i} length")
                key_len = struct.unpack('!H', data[offset:offset+2])[0]
                offset += 2
                if offset + key_len > len(data):
                    raise ValueError(f"Not enough data for key {i}")
                encrypted_keys.append(data[offset:offset+key_len])
                offset += key_len
            
            # Extract IV
            if offset + 16 > len(data):
                raise ValueError("Not enough data for IV")
            iv = data[offset:offset+16]
            offset += 16
            
            # Extract encrypted data
            encrypted_data = data[offset:]
            
            # Try to decrypt one of the AES keys with our private key
            aes_key = None
            for idx, enc_key in enumerate(encrypted_keys):
                try:
                    aes_key = self.private_key.decrypt(
                        enc_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    print(f"🔓 ✅ Decrypted AES key #{idx}")
                    break
                except Exception:
                    continue
            
            if aes_key is None:
                raise ValueError("Could not decrypt message - no valid key found for this node")
            
            # Decrypt data with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
            
            print(f"🔓 DECRYPTED SUCCESS: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            print(f"❌ DECRYPTION FAILED: {e}")
            traceback.print_exc()
            raise

    def extract_timestamp(self, data):
        timestamp = struct.unpack('!Q', data[:8])[0]
        return timestamp
