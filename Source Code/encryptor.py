from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from colorama import Fore, Style, init
import struct, glob
import time
import os
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Cipher import Salsa20
from latency_monitor import LatencyMonitor
from throughput_monitor import ThroughputMonitor

init(autoreset=True)
HAS_CRYPTO = True  # Required by pysyncobj

# Required by pysyncobj
def getEncryptor(password):
    cipher = os.environ.get('SELECTED_CIPHER', 'AES')
    node_count = int(os.environ.get('CLUSTER_NODE_COUNT', '3'))
    AsymmetricEncryptor.set_cipher(cipher)
    return AsymmetricEncryptor(password, node_count)

class SymmetricEncryptor:
    _cipher = None

    @classmethod
    def set_cipher(cls, cipher_name: str):
        cls._cipher = cipher_name

    def __init__(self):
        pass

    def symmetric_encrypt(self, key, data):
        if self._cipher == 'AES':
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return cipher.nonce + tag + ciphertext

        elif self._cipher == 'ChaCha20':
            cipher = ChaCha20.new(key=key)
            ciphertext = cipher.encrypt(data)
            return cipher.nonce + ciphertext

        elif self._cipher == 'Salsa20':
            cipher = Salsa20.new(key=key)
            ciphertext = cipher.encrypt(data)
            return cipher.nonce + ciphertext

    def symmetric_decrypt(self, key, data):
        if self._cipher == 'AES':
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)

        elif self._cipher == 'ChaCha20':
            nonce, ciphertext = data[:8], data[8:]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            return cipher.decrypt(ciphertext)

        elif self._cipher == 'Salsa20':
            nonce, ciphertext = data[:8], data[8:]
            cipher = Salsa20.new(key=key, nonce=nonce)
            return cipher.decrypt(ciphertext)


class AsymmetricEncryptor(SymmetricEncryptor):  # Required by pysyncobj
    def __init__(self, password=None, node_count=None):
        super().__init__()
        self.latency_monitor = LatencyMonitor()
        self.throughput_monitor = ThroughputMonitor()

        # Use CLUSTER_NODE_COUNT env var if node_count not passed directly
        if node_count is None:
            node_count = int(os.environ.get('CLUSTER_NODE_COUNT', '3'))
        self.node_count = node_count

        with open('pki_private_key.pem', 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )

        if isinstance(self.private_key, rsa.RSAPrivateKey):
            self.key_info = f'RSA{self.private_key.key_size}'
        else:
            self.key_info = f'ECC{self.private_key.curve.name}'

        self.public_keys = self._load_all_certificates()
        self.enabled = len(self.public_keys) >= self.node_count
        print(f"Loaded {len(self.public_keys)} certs (need {self.node_count}), encrypt={'ON' if self.enabled else 'OFF'}")

    def _load_all_certificates(self):
        public_keys = {}
        for cert_file in glob.glob('*_certificate.pem'):
            try:
                with open(cert_file, 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                    pub_key = cert.public_key()
                    if isinstance(pub_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
                        public_keys[cert_file.replace('_certificate.pem', '')] = pub_key
                    else:
                        print(f"[SKIP] {cert_file}: Not RSA or ECC cert ({type(pub_key).__name__})")
            except:
                pass
        return public_keys

    def _load_certificates(self):
        new_certs = self._load_all_certificates()
        if len(new_certs) > len(self.public_keys):
            print(f"[CERT REFRESH] Found {len(new_certs) - len(self.public_keys)} new certificates!")
            self.public_keys = new_certs
            self.enabled = len(self.public_keys) >= self.node_count
            if self.enabled:
                print(f"[ENCRYPTION] Now enabled with {len(self.public_keys)} certificates!")

    _raft_context = ""

    @classmethod
    def set_context(cls, label: str):
        cls._raft_context = label

    def _try_unwrap_ecc(self, encrypted_key):
        """Attempt to unwrap a sym_key from an ECC recipient slot using our private key."""
        exchange_pub_len = struct.unpack('!H', encrypted_key[:2])[0]
        exchange_pub_bytes = encrypted_key[2:2+exchange_pub_len]
        wrapped_key = encrypted_key[2+exchange_pub_len:]
        exchange_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            self.private_key.curve, exchange_pub_bytes
        )
        shared_key = self.private_key.exchange(ec.ECDH(), exchange_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return bytes(a ^ b for a, b in zip(wrapped_key, derived_key))

    def encrypt_at_time(self, data, ts):  # Required by pysyncobj
        self.latency_monitor.start_latency()
        self.throughput_monitor.start_throughput()
        try:
            ctx = f"  ← {self._raft_context}" if self._raft_context else ""
            if not self.enabled:
                print(f"SEND {len(data):>5}B  [no encryption]{ctx}")
                return struct.pack('!Q', ts) + data

            print(Fore.YELLOW + f'Pre-Encryption Bytes Size: {len(data)} bytes')

            sym_key = os.urandom(32)
            encrypted_data = self.symmetric_encrypt(sym_key, data)
            packet = struct.pack('!Q', ts) + struct.pack('!H', len(self.public_keys))

            for public_key in self.public_keys.values():
                if isinstance(public_key, rsa.RSAPublicKey):
                    encrypted_key = public_key.encrypt(
                        sym_key,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )

                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    # Generate a fresh ephemeral keypair for this recipient
                    exchange_private_key = ec.generate_private_key(public_key.curve)
                    # ECDH: combine our ephemeral private key with recipient's public key
                    shared_key = exchange_private_key.exchange(ec.ECDH(), public_key)
                    # Derive a 32-byte wrapping key from the shared secret
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(shared_key)
                    # Ephemeral public key goes in the packet so recipient can reproduce the shared secret
                    exchange_pub_bytes = exchange_private_key.public_key().public_bytes(
                        serialization.Encoding.X962,
                        serialization.PublicFormat.UncompressedPoint
                    )
                    # Wrap the sym_key by XORing with the derived key
                    wrapped_key = bytes(a ^ b for a, b in zip(sym_key, derived_key))
                    # Packet: [2-byte ephemeral pub len][ephemeral pub bytes][32-byte wrapped sym_key]
                    encrypted_key = struct.pack('!H', len(exchange_pub_bytes)) + exchange_pub_bytes + wrapped_key

                packet += struct.pack('!H', len(encrypted_key)) + encrypted_key

            packet += encrypted_data
            self.latency_monitor.stop_latency(f'encrypt_{self._cipher}_{self.key_info}')
            self.throughput_monitor.stop_throughput(len(data), f'encrypt_{self._cipher}_{self.key_info}')

            hex_fp = packet[:20].hex()
            print(f"SEND {len(data):>5}B → {len(packet):>5}B  "
                  f"{Fore.RED}{hex_fp}…{Style.RESET_ALL}{ctx}")
            return packet

        except Exception as e:
            print(f"[ERROR] Encrypt: {e}")
            raise

    def decrypt(self, packet):  # Required by pysyncobj
        self.latency_monitor.start_latency()
        self.throughput_monitor.start_throughput()
        try:
            if len(packet) < 14:
                return packet[8:]
            try:
                num_recipients = struct.unpack('!H', packet[8:10])[0]
                if num_recipients == 0 or num_recipients > 100:
                    return packet[8:]
            except:
                return packet[8:]

            print(Fore.YELLOW + f'Pre-Decryption Bytes Size: {len(packet)} bytes')

            # Collect all recipient slots first, then try each one
            offset = 10
            recipient_slots = []
            for _ in range(num_recipients):
                key_length = struct.unpack('!H', packet[offset:offset+2])[0]
                offset += 2
                encrypted_key = packet[offset:offset+key_length]
                offset += key_length
                recipient_slots.append(encrypted_key)

            encrypted_data = packet[offset:]
            sym_key = None

            for encrypted_key in recipient_slots:
                try:
                    if isinstance(self.private_key, rsa.RSAPrivateKey):
                        candidate = self.private_key.decrypt(
                            encrypted_key,
                            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        )
                        # RSA decrypt either works or throws — if we get here it's ours
                        sym_key = candidate
                        break

                    elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
                        candidate = self._try_unwrap_ecc(encrypted_key)
                        # ECC never throws so we must verify by attempting decryption
                        try:
                            result = self.symmetric_decrypt(candidate, encrypted_data)
                            # Decryption succeeded — this is our slot
                            sym_key = candidate
                            # Return early since we already have the decrypted data
                            self.latency_monitor.stop_latency(f'decrypt_{self._cipher}_{self.key_info}')
                            self.throughput_monitor.stop_throughput(len(result), f'decrypt_{self._cipher}_{self.key_info}')
                            ctx = f"  ← {self._raft_context}" if self._raft_context else ""
                            hex_fp = packet[:20].hex()
                            print(f"RECV {len(packet):>5}B → {len(result):>5}B  "
                                  f"{Fore.RED}{hex_fp}…{Style.RESET_ALL}{ctx}")
                            return result
                        except Exception:
                            # Wrong slot — try the next one
                            continue

                except Exception as ex:
                    print(f'[KEY UNWRAP ERROR] {ex}')
                    continue

            if sym_key is None:
                raise ValueError("Could not unwrap symmetric key — no matching recipient slot found")

            decrypted_data = self.symmetric_decrypt(sym_key, encrypted_data)
            self.latency_monitor.stop_latency(f'decrypt_{self._cipher}_{self.key_info}')
            self.throughput_monitor.stop_throughput(len(decrypted_data), f'decrypt_{self._cipher}_{self.key_info}')

            ctx = f"  ← {self._raft_context}" if self._raft_context else ""
            hex_fp = packet[:20].hex()
            print(f"RECV {len(packet):>5}B → {len(decrypted_data):>5}B  "
                  f"{Fore.RED}{hex_fp}…{Style.RESET_ALL}{ctx}")
            return decrypted_data

        except Exception as e:
            print(f"[ERROR] Decrypt: {e}")
            raise

    def extract_timestamp(self, packet):  # Required by pysyncobj
        return struct.unpack('!Q', packet[:8])[0]
