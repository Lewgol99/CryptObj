import socket
import struct
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509

class RSASocket:
    def __init__(self, sock):
        self._sock = sock
        
        # Load your existing RSA keys
        with open('pki_private_key.pem', 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        
        with open('certificate.pem', 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            self.public_key = cert.public_key()
        
        self.chunk_size = 190  # Max for 2048-bit RSA
    
    def send(self, data):
        if not data:
            return 0
        
        # Encrypt in chunks
        chunks = [data[i:i+self.chunk_size] for i in range(0, len(data), self.chunk_size)]
        encrypted = [self.public_key.encrypt(c, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) for c in chunks]
        
        # Send: num_chunks, then each chunk with length
        self._sock.sendall(struct.pack('!I', len(encrypted)))
        for e in encrypted:
            self._sock.sendall(struct.pack('!I', len(e)) + e)
        
        return len(data)
    
    def recv(self, bufsize):
        # Read number of chunks
        n = self._sock.recv(4)
        if not n or len(n) < 4:
            return b''
        num = struct.unpack('!I', n)[0]
        
        # Decrypt each chunk
        result = b''
        for _ in range(num):
            l = self._sock.recv(4)
            if not l:
                return b''
            length = struct.unpack('!I', l)[0]
            
            enc = b''
            while len(enc) < length:
                enc += self._sock.recv(length - len(enc))
            
            result += self.private_key.decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        
        return result
    
    def sendall(self, data):
        return self.send(data)
    
    def __getattr__(self, name):
        return getattr(self._sock, name)

def enable_socket_encryption():
    """Call this before creating Raft - uses RSA with your PKI keys"""
    original = socket.socket
    socket.socket = lambda *a, **k: RSASocket(original(*a, **k))
    print("✓ RSA encryption enabled")
