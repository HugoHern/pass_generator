# pass_generator (Python-focused)

This repository is a small, focused learning project: it generates strong, memorable passwords and demonstrates SHA-256 hashing and safer alternatives using Python so you can learn the differences between hashing and encryption and see hashing in practice.

Warning: The SHA-256 examples in this repo are for learning and deterministic hashing demonstrations only. Do not use plain SHA-256 (or any fast hash) by itself for storing user login passwords in production — use an adaptive KDF such as Argon2 or bcrypt with a unique salt.

Table of contents
- Overview
- Quick start (Python)
- How this repo uses SHA-256 (Python)
- Python examples (generation, SHA-256, PBKDF2)
- Verifying hashes (Python, conceptual)
- Why SHA-256 is not suitable for password storage
- When to use hashing vs encryption
- Security tips (Python-relevant)
- Contributing and license
- Further reading

Overview
This project:
- Generates passwords with configurable options (length, character sets, passphrase-style) using Python's secrets module.
- Computes SHA-256 digests of generated passwords to teach hashing concepts using hashlib.
- Shows a simple, safer example using PBKDF2 (also available in Python's hashlib) so you can compare fast hashing vs an adaptive KDF.

Quick start (Python)
1. Clone the repo:
   git clone https://github.com/HugoHern/pass_generator.git
2. Change into the repo and run the Python examples (adjust filenames if your repository uses different names):
   - Generate + hash: `python generate_and_hash.py --length 16 --symbols`
   - PBKDF2 example: `python pbkdf2_example.py`

How this repo uses SHA-256 (Python)
Search the code for:
- "sha256" or "SHA-256"
- Calls to `hashlib.sha256` or similar

Those locations show where the repository computes the digest. The examples below mirror the patterns used in the code so you can run and experiment locally.

Python examples (runnable, conceptual)

````markdown
# generate_and_hash.py
```python
import secrets
import hashlib
import string
import argparse

def generate_password(length=16, charset=None):
    if charset is None:
        charset = string.ascii_letters + string.digits + "!@#$%^&*()-_"
    return ''.join(secrets.choice(charset) for _ in range(length))

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--length', type=int, default=16)
    p.add_argument('--symbols', action='store_true')
    args = p.parse_args()

    charset = None
    if args.symbols:
        charset = string.ascii_letters + string.digits + "!@#$%^&*()-_"

    pwd = generate_password(args.length, charset)
    print('password:', pwd)
    print('sha256:', sha256_hex(pwd))
```
