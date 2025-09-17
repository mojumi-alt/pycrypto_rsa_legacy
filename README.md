# What is this?
This is a small python library that contains the legacy plain rsa functions from the now dead pycrypto. This project has no affiliation with pycrypto.

$${\color{orange}Plain \space RSA \space is \space insecure, \space  do \space  not use \space  it \space for \space new projects!}$$

# Why
This library might be interesting for you if:
* You want to replace pycrypto with pycryptodome (it is an awesome library!)
* You need to continue using old insecure rsa without any ciphers (pycryptodome deprecated those for a good reason!)
* You need exact compatiblity with pycrypto 
* You need to talk to old systems that are impossible to change but you do not want to pull in a huge cryptography framework

# Installation

We provide pre built wheels for all supported python versions:

    pip install pycrypto_rsa_legacy

# License

The python code in this project is licensed under the terms of the MIT license, the native C implementation links against gmp and therefore falls under the terms of the LGPL-3.0

# Feature support

The following table shows the list of currently supported features compared to pycrypto:

| ✅ | ❌ |
|:---:|:---:| 
| encrypt | blind / unblind |
| decrypt | generate a new rsa key |
| verify | load key from file (.pem or .der) |
| sign | save key to file |
| determine basic key properties
| load key from pycryptodome key

# Usage

This shows a one-in-all example of how to use the various functions:

```python
from Crypto.PublicKey import RSA
from pycrypto_rsa_legacy import PlainRSAKey

# Load key from another crypto implementation...
private_key = PlainRSAKey(key=RSA.import_key(open("private.pem").read()))
public_key = PlainRSAKey(key=RSA.import_key(open("public.pem").read()))

# ...or by setting the key parameters directly
# private_key = PlainRSAKey(n=0, d=0, p=0, q=0, u=0) # p, q, u are optional!
# public_key = PlainRSAKey(n=0, e=0)

# Encrypt some text, the text must be LATIN-1 encodable (i.e not contain any Umlauts, etc)!
message = "hello!"
encrypted = public_key.encrypt(message)

# Decrypt the text
decrypted = private_key.decrypt(encrypted)

# Sign a message
signature = private_key.sign(message)

# Verify a signature
assert public_key.verify(message, signature)

# Check some key properties:

print(public_key.is_private_key)      # False
print(public_key.is_public_key)       # True
print(public_key.max_message_length)  # How many bits of message / ciphertext this key can handle in bits
```

# Building from source

This applies to building from this repository or building from sdist tar file.

## Linux / MinGW

* Ensure you have installed libgmp:

    ```bash
    apt install libgmp-dev # Ubuntu, Debian, ...
    apk install gmp-devel  # Alma, Alpine, ...
    pacman -Sy gmp-devel   # Arch, ...
    vcpkg install gmp      # Windows
    ```

* Build and install:

    ```bash
    # If gmp is not installed in a standard location
    export CFLAGS=-I/path/to/gmp/include
    export LDFLAGS=-L/path/to/gmp/lib

    # Build wheel
    python -m build .

    # Optionally fix wheel if you want to ship it to a different machine
    auditwheel repair dist/pycrypto_rsa_legacy-*.whl

    # Install wheel
    pip install dist/pycrypto_rsa_legacy-*.whl
    ```

## Windows with msvc

* Ensure you have installed libgmp:

    ```powershell
    vcpkg install gmp 
    ```

* Build and install, as always ensure that you run these commands in the developer command prompt that ships with msvc build tools

    ```powershell
        # If gmp is not installed in a standard location
        SET INCLUDE=\path\to\vcpkg\packages\gmp\include
        SET LIB=\path\to\vcpkg\packages\gmp\lib

        # Build wheel
        python -m build .
    
        # Optionally fix wheel if you want to ship it to a different machine
        delvewheel repair dist/pycrypto_rsa_legacy-*.whl

        # Install wheel
        pip install dist/pycrypto_rsa_legacy-*.whl
    ```

# Development

## Setting up an editable install

meson allows setting up an editable install, this means the package is just linked into your installation and is automatically rebuilt everytime you make a change (even the native code!)

Ensure that you have meson and ninja installed before running this:

```bash
python -m pip install --no-build-isolation --editable .
```

## Running tests

After setting up the installation as described above simply run:

```bash
python -m unittest discover ./tests/ -v
```