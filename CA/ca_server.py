from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from certificate_authority import CertificateAuthority
import threading
import os

app = Flask(__name__)
lock = threading.Lock()
certs = 'issued certificates'
os.makedirs(certs, exist_ok=True)
ca = CertificateAuthority()
ca.generate_ca_keys()
ca.create_root_certificate()

@app.route("/")
def server_status():
    return {
        "service": 'CA Server',
        "status": 'Connected'
    }

@app.route('/sign_csr', methods=['POST'])
def sign_csr():
    data = request.get_json()
    csr_pem = data.get('csr')
    node_name = data.get('node_name')
    with lock:
        with open('csr.pem', 'wb') as f:
            f.write(csr_pem.encode())
        csr = ca.load_csr()
        if csr:
            cert = ca.sign_csr(csr)
            if cert:
                cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
                os.makedirs('issued_certificates', exist_ok=True)
                with open(f'issued_certificates/{node_name}_certificate.pem', 'w') as f:
                    f.write(cert_pem)
                print(f'✓ Stored {node_name}_certificate.pem')
                return jsonify({'certificate': cert_pem}), 200
    return jsonify({'Error': 'Failed'}), 500
