from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from certificate_authority import CertificateAuthority

app = Flask(__name__)

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
    
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
