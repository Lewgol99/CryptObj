## PyCryptObj Protocol

The objectives of the CryptObj protocol are to implement key wrapping by use of Asymmetric and Symmetric Cryptography into the Raft protocol using PySyncObj and deployed within SEED Internet Emulator to authenticate nodes and secure data in transit to be used for log replication in consensus deployed in distributed systems. This validates NIST security properties such as Authentication and Confidentiality for information security and can be used as a computer network protocol for security applications. The dependencies for the protocol can be viewed and installed in the requirements.txt. 

<table>
  <tr>
    <td><img width="439" alt="Description A" src="https://github.com/user-attachments/assets/bb0b39de-3c34-4e38-aa24-d9ed694e55c9" /></td>
    <td><img width="421" alt="Description B" src="https://github.com/user-attachments/assets/cb0a6ece-6c08-4bc7-a05d-09a83b98f990" /></td>
  </tr>
</table>

## Original Projects

![GitHub](https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white)

Original PySyncObj:

```python
 https://github.com/bakwc/PySyncObj
```

SEED Internet Emulator:

```python
 https://github.com/seed-labs/seed-emulator
```


## Getting Started

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

This protocol can be automatically executed by running scale_peering.py within the Scalability Evaluation directory. The script allows for the quantity of nodes to be changed, as well as the Asymmetric Techniques by specifying RSA with the key size or ECC with the curve, and Symmetric Techniques such as AES or ChaCha20.  

Alternatively, to run manually with nodes.json, copy the new source code files to replace the ones from the original PySyncObj project. 


```python
cp transport.py /usr/local/lib/python3.8/dist-packages/pysyncobj/transport.py 
```

```python
cp encryptor.py /usr/local/lib/python3.8/dist-packages/pysyncobj/encryptor.py
```

To run the system with Hybrid Cryptography, ensure the node name, asymmetric cipher, options for the key size or curve, and symmetric cipher must be defined as a command line arguement.

```python
python3 ./pysyncobj+.py <node_name> <asymmetric_cipher> [options] <symmetric_cipher>
```
Two optional flags can be appended after these arguments:

<img width="150" height="55" alt="image" src="https://github.com/user-attachments/assets/31af7ea3-f71a-4d66-ad58-c738a0602765" />

--no-crypto disables encryption entirely and runs the system in plaintext, for baseline comparison.

```python
python3 ./pysyncobj+.py <node_name> <asymmetric_cipher> [options] <symmetric_cipher> --no-crypto
```

<img width="150" height="55" alt="image" src="https://github.com/user-attachments/assets/32f51608-420e-47c9-8019-ce5bbb46104a" />


--tls runs the system using TLS 1.3 instead of Hybrid Cryptography, and requires an ECC curve as its value.

```python
python3 ./pysyncobj+.py <node_name> <asymmetric_cipher> [options] <symmetric_cipher> --tls <curve>
```


## Analysis Output

CryptObj generates CSV outputs that contain:
- Encryption and Decryption Time (ms)
- Signing and Verification Time (ms) 

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## Publications
[![Google Scholar](https://img.shields.io/badge/Google%20Scholar-4285F4?style=for-the-badge&logo=google-scholar&logoColor=white)](https://scholar.google.com/citations?user=hA6XGAQAAAAJ&hl=en)

```python

```

## License
[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)
