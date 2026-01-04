# DRT Global Encryptor

A robust command-line tool for file encryption, RSA key management, hybrid encryption, and steganography.

## Features

*   **Symmetric File Encryption (AES-GCM)**: Securely encrypt/decrypt files where you hold the key (single user).
*   **Hybrid File Encryption (AES + RSA)**: Encrypt **ENTIRE FILES** (code, videos, etc.) specifically for a recipient using their Public Key. Only they can open it with their Private Key.
*   **Steganography**: Hide private keys (or any small file) inside **Images (.png)** or **Audio (.wav)**.
*   **Metadata Preservation**: Retains original file extensions and attributes.
*   **Educational Mode**: Learn about public/private keys and encryption concepts.

## Installation

### Option 1: MacOS Installer (Recommended)
1.  Run the `build_pkg.sh` script to create an installer (requires python/pyinstaller).
2.  Double-click `drtencrypt.pkg` to install.
3.  Run `drtencrypt` from any terminal.

### Option 2: Run from Source
1.  Clone the repository.
2.  Create a virtual environment: `python3 -m venv .venv`
3.  Install dependencies: `.venv/bin/pip install -r requirements.txt`
4.  Run the script: `.venv/bin/python drt_encryptor.py`

## Usage

### 1. Symmetric Encryption (Self)
Use this when you just want to lock a file for yourself or someone sharing the same `secret.key`.

```bash
drtencrypt encrypt secrets.txt
drtencrypt decrypt secrets.drt
```

### 2. Hybrid Encryption (Send to User)
Use this to securely send a file (e.g., source code, video) to someone else. You only need their **Public Key**.

**Sender (You):**
```bash
drtencrypt send-to critical_code.py recipient_public_key.pem
```
*Creates `critical_code.py.drt-rsa`.*

**Recipient (Them):**
```bash
drtencrypt receive critical_code.py.drt-rsa their_private_key.pem
```
*Restores `critical_code.py`.*

### 3. RSA Key Management
Generate keys for yourself. Share the `public_key.pem` with others so they can send you files. Keep `private_key.pem` secret!

```bash
drtencrypt rsa-gen --out .
```

### 4. RSA Message Encryption
Best for very short text messages (passwords, short codes).

```bash
drtencrypt rsa-encrypt public_key.pem "Secret spy message"
```

### 5. Steganography (Hide Keys)
Hide your `private_key.pem` (or any small file) inside a media file to avoid detection. Supports **PNG** images and **WAV** audio.

**Hide:**
```bash
drtencrypt stego-hide source.png private_key.pem stego_output.png
# OR
drtencrypt stego-hide song.wav  private_key.pem stego_song.wav
```

**Unlock & Decrypt Message:**
Extracts the key from the media and uses it to decrypt a short base64 message.
```bash
drtencrypt stego-unlock stego_song.wav "<PASTE_BASE64_HERE>"
```

### 6. Learn
```bash
drtencrypt explain
```

## Security Note
This tool uses standard cryptographic libraries (`cryptography` package in Python) but is intended for educational and personal use. Keep your `secret.key` and `private_key.pem` safe!
