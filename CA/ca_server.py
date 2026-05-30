from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_csr
from certificate_authority import CertificateAuthority
import threading
import os

app = Flask(__name__)
lock = threading.Lock()
certs = 'issued_certificates'
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
    try:
        csr = load_pem_x509_csr(csr_pem.encode())
        with lock:
            cert = ca.sign_csr(csr)
        if cert:
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            with open(f'issued_certificates/{node_name}_certificate.pem', 'w') as f:
                f.write(cert_pem)
            print(f'✓ Stored {node_name}_certificate.pem')
            return jsonify({'certificate': cert_pem}), 200
    except Exception as e:
        print(f'Error: {e}')
    return jsonify({'Error': 'Failed'}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, threaded=True)
