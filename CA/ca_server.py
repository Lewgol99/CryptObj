from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from certificate_authority import CertificateAuthority
import os

app = Flask(__name__)

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

    with open('csr.pem', 'wb') as f:
        f.write(csr_pem.encode())

    csr = ca.load_csr()
    if csr:
        cert = ca.sign_csr(csr)
        if cert:
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            return jsonify({'certificate': cert_pem}), 200
    
    return jsonify({'Error': 'Failed'}), 500
    
@app.route('/api/get_all_certificates', methods=['GET'])
def get_all_certificates():
    """Return all issued certificates"""
    certificates = {}
    
    # Read all .pem files from issued_certificates directory
    for filename in os.listdir(CERTS_DIR):
        if filename.endswith('_certificate.pem'):
            node_name = filename.replace('_certificate.pem', '')
            with open(f'{certs}/{filename}', 'r') as f:
                certificates[node_name] = f.read()
    
    return jsonify({'certificates': certificates})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
