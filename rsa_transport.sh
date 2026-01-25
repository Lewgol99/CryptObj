#!/bin/bash
cp transport.py $(python3 -c "import pysyncobj, os; print(os.path.dirname(pysyncobj.__file__))")/transport.py
echo "✓ RSA Transport Installed!"
