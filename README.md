## CryptObj Protocol

The objectives of CryptObj project are to implement key wrapping by use of Asymmetric and Symmetric Cryptography into the protocol to secure and encapsulate data in transit to be used for state replication in consensus deployed in distributed systems. This validates NIST security properties for information security and can be used as a network protocol for security applications.  

<img width="439" height="333" alt="image" src="https://github.com/user-attachments/assets/bb0b39de-3c34-4e38-aa24-d9ed694e55c9" />


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

This protocol can be automatically executed by running scale_peering.py within the Scalability Evaluation directory. The script allows for the quantity of nodes to be changed, as well as the asymmetric techniques by specifying RSA with the key size or ECC with the curve, and symmetric techniques such as AES or ChaCha20.  

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)


Alternatively, to run manually with nodes.json, copy the new source code files to replace the ones from the original PySyncObj project. 


```python
cp transport.py /usr/local/lib/python3.8/dist-packages/pysyncobj/transport.py 
```

```python
cp encryptor.py /usr/local/lib/python3.8/dist-packages/pysyncobj/encryptor.py
```

To run the system ensure the node name, asymmetric cipher, options for the key size or curve, and symmetric cipher must be defined as a command line arguement. 

```python
python3 ./pysyncobj+.py <node_name> <asymmetric cipher> [options] <symmetric_cipher> 
```


## Publications
[![Google Scholar](https://img.shields.io/badge/Google%20Scholar-4285F4?style=for-the-badge&logo=google-scholar&logoColor=white)](https://scholar.google.com/citations?user=hA6XGAQAAAAJ&hl=en)

```python

```

## License
[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)
