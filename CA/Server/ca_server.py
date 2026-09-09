from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_csr
from certificate_authority import CertificateAuthority
import threading
import os

app = Flask(__name__)
lock = threading.Lock()
os.makedirs('issued_certificates', exist_ok=True)
ca = CertificateAuthority()
ca.generate_ca_keys()
ca.create_root_certificate()
ca.save_certificate(ca.root_cert)

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
            print(f'✓ Stored {node_name}_certificate.pem (requested by {request.remote_addr})', flush=True)
            return jsonify({'certificate': cert_pem}), 200
    except Exception as e:
        print(f'Error: {e}')
    return jsonify({'Error': 'Failed'}), 500

@app.route('/get_certificate/<node_name>')
def get_certificate(node_name):
    cert_path = f'issued_certificates/{node_name}_certificate.pem'
    if os.path.exists(cert_path):
        print(f'[get_certificate] served {node_name} to {request.remote_addr}', flush=True)
        with open(cert_path, 'r') as f:
            return jsonify({'certificate': f.read()}), 200
    print(f'[get_certificate] 404 for {node_name} (requested by {request.remote_addr})', flush=True)
    return jsonify({'error': 'Not found'}), 404

@app.route('/get_root_certificate')
def get_root_certificate():
    if os.path.exists('certificate.pem'):
        print(f'[get_root_certificate] served root cert to {request.remote_addr}', flush=True)
        with open('certificate.pem', 'r') as f:
            return jsonify({'certificate': f.read()}), 200
    print(f'[get_root_certificate] 404 (requested by {request.remote_addr})', flush=True)
    return jsonify({'error': 'Not found'}), 404
