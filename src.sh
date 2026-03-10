#!/bin/bash
cp transport.py $(python3 -c "import pysyncobj, os; print(os.path.dirname(pysyncobj.__file__))")/transport.py
echo "✓ RSA and ECC Transport Installed!"

cp encryptor.py $(python3 -c "import pysyncobj, os; print(os.path.dirname(pysyncobj.__file__))")/encryptor.py
echo "✓ RSA and ECC Encryptor Installed!"
