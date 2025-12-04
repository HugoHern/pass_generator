# pass_generator

pass_generator is a small, focused project to generate strong, memorable passwords and to help you understand the principles of password encryption and secure storage. This repository is intended both as a practical tool and as a learning resource for developers and users who want to improve their password security.

## Table of Contents

- [Project Goals](#project-goals)
- [Features](#features)
- [Quick Start](#quick-start)
- [How It Generates Strong Passwords](#how-it-generates-strong-passwords)
- [Password Encryption vs Hashing (What to use and when)](#password-encryption-vs-hashing-what-to-use-and-when)
- [Security Best Practices](#security-best-practices)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Project Goals

- Provide a simple and reliable way to generate strong passwords for personal and developer use.
- Explain password encryption and secure storage practices so users understand trade-offs and choose safe approaches.
- Offer configurable options (length, character sets, pronounceability hints) so generated passwords fit different use-cases.

## Features

- Configurable password length and allowed character sets (upper, lower, numbers, symbols).
- Options for generating fully random or more memorable (pattern/pronounceable) passwords.
- Explanatory documentation on encryption, hashing, and storage best practices.
- Example code snippets showing how to securely encrypt or hash passwords for different needs.

## Quick Start

1. Clone this repo:
   git clone https://github.com/HugoHern/pass_generator.git
2. Inspect the README and the generated example scripts in the project.
3. Run the generator (example — replace with actual command for your implementation):
   - Node.js example: `node generate.js --length 16 --symbols`
   - Python example: `python generate.py --length 16 --symbols`

(Adjust the command above to the language and entry point used in this repository.)

## How It Generates Strong Passwords

A strong password is primarily about unpredictability (entropy) and length. This project uses a cryptographically secure random source (e.g., crypto.randomBytes in Node.js or secrets in Python) to select characters from the configured character set.

Key guidelines:
- Prefer length over obscure character sets: a 16+ character password from a large character set is typically stronger than a shorter password with symbols.
- Aim for at least 60–80 bits of entropy for long-term secrets; for many accounts, 80+ bits is recommended.
- Avoid using predictable patterns or reused passwords across sites.

## Password Encryption vs Hashing (What to use and when)

- Hashing (one-way): Use for verifying passwords you accept from users (login). Use slow, adaptive algorithms like Argon2, bcrypt, or PBKDF2 with a unique per-password salt. This is not reversible.
- Encryption (two-way): Use only when you need to recover the original secret (e.g., storing an API key you must use). Use authenticated encryption (AES-256-GCM or ChaCha20-Poly1305) with secure key management. If possible, avoid storing reversible secrets at all.
- General rule: For user passwords, always hash. For secrets you must retrieve and use, encrypt with a well-protected key.

## Security Best Practices

- Never log plaintext passwords.
- Do not embed encryption keys in source code or commit them. Use environment variables, a secret manager, or a hardware security module.
- Use unique salts and appropriate work factors for hashing (e.g., bcrypt cost, Argon2 memory/time settings).
- Use a cryptographically secure RNG for generation (do not use Math.random or insecure generators).
- Educate users to use a password manager to store unique passwords per site.

## Examples

- Generate a 16-character password with upper/lower/numbers/symbols:
  `generate --length 16 --upper --lower --numbers --symbols`

- Generate a pronounceable/passphrase-like password:
  `generate --words 4 --separator "-"`

- Hashing example (conceptual):
  - Argon2: argon2.hash(password, { salt, time, memory, parallelism })

- Encryption example (conceptual):
  - AES-GCM: encrypt(plaintext, key, nonce) -> ciphertext + tag

(See the repo's code for runnable examples and implementation-specific usage.)

## Contributing

Contributions are welcome. Please:
- Open an issue to discuss feature requests or bugs.
- Follow the code style used in the repository and include tests where appropriate.
- Do not commit secrets or private keys.

## License

Specify your license here (e.g., MIT). If you want, I can add a LICENSE file for you.

## Further Reading

- OWASP Password Storage Cheat Sheet — guidance on hashing and storage.
- NIST Digital Identity Guidelines — recommendations for password policies.
- RFC 8017 (PKCS #1) and modern cryptography libraries docs for encryption/hashing implementation details.

If you'd like, I can:
- Tailor the Quick Start commands to match the exact language and entry points in this repository.
- Commit this README.md to the repository for you.
- Add example scripts that demonstrate Argon2 hashing and AES-GCM encryption with secure key handling.
