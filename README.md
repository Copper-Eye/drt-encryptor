# DRT Encryptor

A powerful, military-grade file encryption tool for macOS.
Secures any file type with **AES-256-GCM** encryption while preserving original metadata (creation dates, permissions) and extensions.

## Features

- **Military Grade Security**: Uses AES-256-GCM with a 256-bit unique machine key.
- **Smart Mode**: Automatically detects whether to encrypt or decrypt based on the file extension.
    - `drtencrypt file.txt` -> Encrypts to `file.drt`
    - `drtencrypt file.drt` -> Decrypts to `file.txt`
- **Metadata Preservation**: Retains original Maintained/Creation dates and file permissions to prevent data corruption.
- **Global Command**: Installs as a native command line tool.

## Installation

### Option 1: Installer (Recommended)
Download the latest `drtencrypt.pkg` from the [Releases](.) page and install it.

### Option 2: From Source
1.  Clone the repository.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run the script wrapper:
    ```bash
    ./drtencrypt target_file
    ```

## Usage

Simply run `drtencrypt` followed by the file you want to process.

```bash
# To Encrypt
drtencrypt my_secret_photo.jpg
# Output: my_secret_photo.drt (original removed)

# To Decrypt
drtencrypt my_secret_photo.drt
# Output: my_secret_photo.jpg (original restored with correct date)
```

## Security Note

The encryption key is generated uniquely for your machine and stored at:
`~/.drtencryptor/secret.key`

**Backup this key!** If you lose this key or delete the folder, your encrypted files cannot be recovered.
