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

# Initialize colorama for cross-platform color support
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama not available
    class Fore:
        RED = '\033[31m'
        MAGENTA = '\033[35m'
    class Style:
        RESET_ALL = '\033[0m'

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
        Pure RSA asymmetric encryption with chunking - encrypt data for each peer using their public key
        If data is larger than RSA limit, split into chunks
        """
        try:
            # === SHOW PLAINTEXT BEFORE ENCRYPTION ===
            plaintext_preview = data[:80] if len(data) <= 80 else data[:80] + b'...'
            print(f"\n📤 SENDING: Plaintext ({len(data)} bytes)")
            print(f"   {Fore.MAGENTA}{plaintext_preview}{Style.RESET_ALL}")
            print(f"   ⬇️ ENCRYPTING...")
            
            # Check for new certificates
            self._load_certificates()
            
            # If still no encryption, use passthrough
            if not self.encryption_enabled:
                print(f"⚠️  PASSTHROUGH: only {len(self.public_keys)} cert(s), need 2+")
                timestamp_bytes = struct.pack('!Q', timestamp)
                return timestamp_bytes + data
            
            # RSA-2048 with OAEP can encrypt max ~214 bytes
            # RSA-4096 with OAEP can encrypt max ~446 bytes
            # Use conservative limit of 190 bytes to be safe
            MAX_CHUNK_SIZE = 190
            
            # Split data into chunks if needed
            data_chunks = []
            if len(data) <= MAX_CHUNK_SIZE:
                data_chunks = [data]
                print(f"🔐 RSA ENCRYPTING {len(data)} bytes (1 chunk) for {len(self.public_keys)} peers")
            else:
                for i in range(0, len(data), MAX_CHUNK_SIZE):
                    data_chunks.append(data[i:i+MAX_CHUNK_SIZE])
                print(f"🔐 RSA ENCRYPTING {len(data)} bytes ({len(data_chunks)} chunks) for {len(self.public_keys)} peers")
            
            timestamp_bytes = struct.pack('!Q', timestamp)
            
            # Package format:
            # [timestamp:8][peer_count:2][num_data_chunks:2]
            # For each peer: [peer_chunk_count:2][chunk1_len:2][chunk1][chunk2_len:2][chunk2]...
            result = timestamp_bytes
            result += struct.pack('!H', len(self.public_keys))  # peer_count
            result += struct.pack('!H', len(data_chunks))  # num_data_chunks
            
            # Encrypt each data chunk for each peer
            for peer_name, public_key in self.public_keys.items():
                peer_encrypted_chunks = []
                
                for chunk_idx, data_chunk in enumerate(data_chunks):
                    encrypted_chunk = public_key.encrypt(
                        data_chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    peer_encrypted_chunks.append(encrypted_chunk)
                
                print(f"🔐   Encrypted {len(data_chunks)} chunk(s) for peer: {peer_name}")
                
                # Store this peer's encrypted chunks
                result += struct.pack('!H', len(peer_encrypted_chunks))
                for enc_chunk in peer_encrypted_chunks:
                    result += struct.pack('!H', len(enc_chunk))
                    result += enc_chunk
            
            # === SHOW CIPHERTEXT AFTER ENCRYPTION ===
            print(f"   ✅ Encrypted to {len(result)} bytes")
            print(f"🔒 CIPHERTEXT SENT: {Fore.RED}{result[:40].hex()}...{Style.RESET_ALL}\n")
            return result
            
        except Exception as e:
            print(f"❌ ENCRYPTION FAILED: {e}")
            traceback.print_exc()
            raise

    def decrypt(self, data):
        """
        Decrypt using THIS node's RSA private key - or passthrough if encryption not enabled
        Handles chunked data for large messages
        """
        try:
            # === SHOW CIPHERTEXT BEFORE DECRYPTION ===
            print(f"\n📥 CIPHERTEXT RECEIVED: {Fore.RED}{data[:50].hex()}...{Style.RESET_ALL} ({len(data)} bytes)")
            
            # Check for new certificates
            self._load_certificates()
            
            # Check if this is encrypted data or passthrough data
            if len(data) < 14:  # Need at least timestamp + peer_count + num_chunks
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
            
            offset += 2
            
            # Read number of data chunks
            try:
                num_data_chunks = struct.unpack('!H', data[offset:offset+2])[0]
                if num_data_chunks == 0 or num_data_chunks > 100:
                    print(f"🔓 PASSTHROUGH (invalid num_data_chunks={num_data_chunks}): {len(data)} bytes")
                    return data[8:]
                offset += 2
            except:
                print(f"🔓 PASSTHROUGH (cannot read num_data_chunks): {len(data)} bytes")
                return data[8:]
            
            print(f"\n📥 RECEIVED: Ciphertext ({len(data)} bytes)")
            print(f"   {Fore.RED}{data[:40].hex()}...{Style.RESET_ALL}")
            print(f"   ⬇️ DECRYPTING {peer_count} peer(s), {num_data_chunks} chunk(s)...")
            
            # Extract encrypted chunks for each peer
            all_peer_chunks = []
            for peer_idx in range(peer_count):
                # Read chunk count for this peer
                if offset + 2 > len(data):
                    raise ValueError(f"Not enough data for peer {peer_idx} chunk count")
                peer_chunk_count = struct.unpack('!H', data[offset:offset+2])[0]
                offset += 2
                
                peer_chunks = []
                for chunk_idx in range(peer_chunk_count):
                    if offset + 2 > len(data):
                        raise ValueError(f"Not enough data for peer {peer_idx} chunk {chunk_idx} length")
                    chunk_len = struct.unpack('!H', data[offset:offset+2])[0]
                    offset += 2
                    if offset + chunk_len > len(data):
                        raise ValueError(f"Not enough data for peer {peer_idx} chunk {chunk_idx}")
                    peer_chunks.append(data[offset:offset+chunk_len])
                    offset += chunk_len
                
                all_peer_chunks.append(peer_chunks)
            
            # Try to decrypt chunks using our private key
            decrypted_chunks = None
            for peer_idx, peer_chunks in enumerate(all_peer_chunks):
                try:
                    # Try to decrypt all chunks for this peer
                    temp_decrypted = []
                    for chunk_idx, encrypted_chunk in enumerate(peer_chunks):
                        decrypted_chunk = self.private_key.decrypt(
                            encrypted_chunk,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        temp_decrypted.append(decrypted_chunk)
                    
                    # If we got here, all chunks decrypted successfully
                    decrypted_chunks = temp_decrypted
                    print(f"🔓 ✅ Successfully decrypted {len(decrypted_chunks)} chunk(s) from peer #{peer_idx}")
                    break
                except Exception:
                    # This peer's chunks weren't for us, try next peer
                    continue
            
            if decrypted_chunks is None:
                raise ValueError("Could not decrypt message - no valid chunks found for this node")
            
            # Reassemble the original data from chunks
            plaintext = b''.join(decrypted_chunks)
            
            # === SHOW PLAINTEXT AFTER DECRYPTION ===
            print(f"   ✅ Decrypted to {len(plaintext)} bytes")
            plaintext_preview = plaintext[:60] if len(plaintext) <= 60 else plaintext[:60] + b'...'
            print(f"📜 PLAINTEXT: {Fore.MAGENTA}{plaintext_preview}{Style.RESET_ALL}")
            
            # === SHOW COUNTER VALUE IF PRESENT ===
            try:
                import pickle, zlib
                decompressed = zlib.decompress(plaintext)
                data_obj = pickle.loads(decompressed)
                
                # Check if it's actual counter operation (not just heartbeat)
                if isinstance(data_obj, dict) and data_obj.get('type') == 'append_entries':
                    if data_obj.get('entries'):
                        print(f"   💾 Replicated {len(data_obj['entries'])} log entries")
                elif isinstance(data_obj, tuple) and len(data_obj) >= 2:
                    method, args = data_obj[0], data_obj[1]
                    print(f"   🎯 RPC Call: {method}{args}")
            except:
                pass  # Not counter data or failed to decode
            
            print()  # Blank line for readability
            
            print(f"🔓 RSA DECRYPTED SUCCESS: {len(plaintext)} bytes")
            return plaintext
            
        except Exception as e:
            print(f"❌ DECRYPTION FAILED: {e}")
            traceback.print_exc()
            raise

    def extract_timestamp(self, data):
        timestamp = struct.unpack('!Q', data[:8])[0]
        return timestamp
