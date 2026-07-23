import struct
import ssl
import pickle
import zlib
from colorama import Fore, Style, init

init(autoreset=True)

_warned_no_set_ciphersuites = False

def _apply_cipher_suite(ctx, cipher_suite, peer_node_name):
    global _warned_no_set_ciphersuites
    if not cipher_suite:
        return
    if hasattr(ctx, 'set_ciphersuites'):
        ctx.set_ciphersuites(cipher_suite)
    elif not _warned_no_set_ciphersuites:
        _warned_no_set_ciphersuites = True
        print(f"{Fore.YELLOW}[TLS_Session] This Python build's ssl module has no "
              f"set_ciphersuites() — cannot enforce a specific TLS 1.3 cipher "
              f"suite. Falling back to default negotiation.{Style.RESET_ALL}")

class TLS_Session:
    def __init__(self, self_node_name, peer_node_name, is_client,
                 self_cert_file, self_key_file, ca_cert_file, latency_monitor,
                 cipher_suite=None, curve_name=None):
        self.peer_node_name = peer_node_name
        self.handshake_complete = False
        self._pending_plaintext_out = []
        self.latency_monitor = latency_monitor
        self.curve_name = curve_name

        self.in_bio = ssl.MemoryBIO()
        self.out_bio = ssl.MemoryBIO()

        if is_client:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            _apply_cipher_suite(ctx, cipher_suite, peer_node_name)
            ctx.load_verify_locations(cafile=ca_cert_file)
            self.sslobj = ctx.wrap_bio(self.in_bio, self.out_bio,
                                        server_hostname=peer_node_name)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            _apply_cipher_suite(ctx, cipher_suite, peer_node_name)
            ctx.load_cert_chain(certfile=self_cert_file, keyfile=self_key_file)
            self.sslobj = ctx.wrap_bio(self.in_bio, self.out_bio, server_side=True)

        self._try_complete_handshake()

    def _tls_info(self):
        if not self.handshake_complete:
            return "handshake in progress"
        cipher = self.sslobj.cipher()
        cipher_name = cipher[0] if cipher else "?"
        version = self.sslobj.version() or "?"
        curve = self.curve_name or "?"
        return f"{version} {cipher_name} curve(configured)={curve}"

    def _try_complete_handshake(self):
        if self.handshake_complete:
            return
        try:
            self.sslobj.do_handshake()
            self.handshake_complete = True
        except ssl.SSLWantReadError:
            pass
        except Exception:
            import traceback
            print(f"{Fore.RED}[TLS_Session._try_complete_handshake] handshake failed for peer "
                  f"{self.peer_node_name} (in_bio_pending={self.in_bio.pending}):{Style.RESET_ALL}")
            traceback.print_exc()
            raise

    def encrypt_at_time(self, data, timestamp):
        self.latency_monitor.start_latency()

        if not self.handshake_complete:
            self._pending_plaintext_out.append(data)
            self._try_complete_handshake()
            if self.handshake_complete:
                payload = b''.join(self._pending_plaintext_out)
                self._pending_plaintext_out = []
            else:
                payload = None
        elif self._pending_plaintext_out:
            payload = b''.join(self._pending_plaintext_out) + data
            self._pending_plaintext_out = []
        else:
            payload = data

        if payload:
            written = 0
            while written < len(payload):
                written += self.sslobj.write(payload[written:])

        out_bytes = self.out_bio.read()
        frame = struct.pack('!Q', timestamp) + struct.pack('!I', len(out_bytes)) + out_bytes
        self.latency_monitor.stop_latency(f'encrypt_TLS1.3_{self.peer_node_name}')
        self.latency_monitor.save_file('latency_measurements')

        hex_fp = frame[:20].hex()
        sent_len = len(payload) if payload else 0
        print(f"SEND {sent_len:>5}B → {len(frame):>5}B  "
              f"[{self._tls_info()}]  "
              f"{Fore.RED}{hex_fp}…{Style.RESET_ALL}  ← {self.peer_node_name}")

        return frame

    def extract_timestamp(self, data):
        try:
            return struct.unpack('!Q', data[:8])[0]
        except Exception:
            import traceback
            print(f"{Fore.RED}[TLS_Session.extract_timestamp] error for peer {self.peer_node_name}:{Style.RESET_ALL}")
            traceback.print_exc()
            raise

    def decrypt(self, data):
        try:
            self.latency_monitor.start_latency()

            data = data[8:]

            length = struct.unpack('!I', data[:4])[0]
            payload = data[4:4 + length]
            if payload:
                self.in_bio.write(payload)

            if not self.handshake_complete:
                self._try_complete_handshake()

            plaintext = bytearray()
            if self.handshake_complete:
                try:
                    while True:
                        chunk = self.sslobj.read(65536)
                        if not chunk:
                            break
                        plaintext += chunk
                except ssl.SSLWantReadError:
                    pass

            self.latency_monitor.stop_latency(f'decrypt_TLS1.3_{self.peer_node_name}')
            self.latency_monitor.save_file('latency_measurements')

            hex_fp = data[:20].hex()
            print(f"RECV {len(data):>5}B → {len(plaintext):>5}B  "
                  f"[{self._tls_info()}]  "
                  f"{Fore.RED}{hex_fp}…{Style.RESET_ALL}  ← {self.peer_node_name}")

            if not plaintext:
                return zlib.compress(pickle.dumps(None))

            return bytes(plaintext)
        except Exception:
            import traceback

            raw_hex = data.hex()
            print(f"{Fore.RED}[TLS_Session.decrypt] error for peer {self.peer_node_name} "
                  f"(data_len={len(data)}, handshake_complete={self.handshake_complete}):{Style.RESET_ALL}")
            print(f"{Fore.RED}  raw bytes (post-timestamp-strip): {raw_hex}{Style.RESET_ALL}")
            traceback.print_exc()
            raise
