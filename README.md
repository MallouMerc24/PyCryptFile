# PyCryptFile
A simple Python tool for encrypting and decrypting files using the Fernet symmetric encryption algorithm

A simple file encryption and decryption tool built with [cryptography’s Fernet](https://cryptography.io/en/latest/fernet/).  
This script can encrypt any file and later decrypt it back to its original form using a secure key.

Features
- Generate a strong random encryption key.
- Save and load encryption keys from a `.key` file.
- Encrypt any file (text, image, etc.).
- Decrypt files back to their original state.
- Uses AES (via Fernet) for secure symmetric encryption.

Requirements 
- Python 3.8+
- cryptography library

Install dependencies with:
```bash
pip install cryptography
