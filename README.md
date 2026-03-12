## PySyncObj+ Protocol

The objectives of PySyncObj+ project is to implement Asymmetric and Symmetric Encryption into the protocol for secure consensus in distributed systems. This validates NIST security properties for information security and can be used as a network protocol for security applications.  

<img width="431" height="330" alt="image" src="https://github.com/user-attachments/assets/c075198d-4593-47c9-a670-bdee7a0f4c23" />


## Getting Started

git clone token: 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

cp transport.py /usr/local/lib/python3.8/dist-packages/pysyncobj/transport.py 
cp encryptor.py /usr/local/lib/python3.8/dist-packages/pysyncobj/encryptor.py

1. OPen all files in the directory!

find . -mindepth 2 -type f -exec mv -t . {} +

2. Copy the new source code files that include the cryptography to PySyncObj!

./src.sh

Remember to remove any existing certificate files or key files. 

rm -rf *.pem


lftp -u Lewgol99 -e "set ssl:verify-certificate no; set ftp:ssl-protect-data true; set ftp:ssl-force true" 192.168.0.17 put latency_measurements.csv


## Publications

## License
