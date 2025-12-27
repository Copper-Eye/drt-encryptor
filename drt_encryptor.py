import os
import struct
import json
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_DIR = Path.home() / ".drtencryptor"
KEY_FILE = KEY_DIR / "secret.key"

def load_key():
    if not KEY_FILE.exists():
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        # AES-256 requires a 32-byte key
        key = AESGCM.generate_key(bit_length=256)
        try:
            with open(KEY_FILE, "wb") as f:
                f.write(key)
            print(f"Key generated and saved to {KEY_FILE}")
        except Exception as e:
            print(f"Error saving key: {e}")
            exit(1)
    else:
        try:
            with open(KEY_FILE, "rb") as f:
                key = f.read()
            if len(key) != 32:
                print(f"Warning: Existing key at {KEY_FILE} is not 32 bytes (256-bit). It might be an old key.")
        except Exception as e:
            print(f"Error loading key: {e}")
            exit(1)
    return key

def encrypt_file(file_path, key):
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {path}")
        return

    try:
        # Capture metadata
        stat_info = os.stat(path)
        mtime = stat_info.st_mtime
        mode = stat_info.st_mode
        
        with open(path, "rb") as f:
            data = f.read()

        # Create Metadata Header
        header = {
            "ext": path.suffix,
            "mtime": mtime,
            "mode": mode
        }
        header_bytes = json.dumps(header).encode('utf-8')
        header_len = len(header_bytes)
        
        # Format: [4 bytes header len][header bytes][12 bytes nonce][encrypted content]
        
        # AES-GCM Encryption of content
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Assemble final payload
        # using 'I' for unsigned int (4 bytes) for header length
        final_data = struct.pack("I", header_len) + header_bytes + nonce + ciphertext

        new_path = path.with_suffix(".drt")
        with open(new_path, "wb") as f:
            f.write(final_data)
        
        # Remove original file
        os.remove(path)
        print(f"Encrypted: {path} -> {new_path}")
    except Exception as e:
        print(f"Error encrypting {path}: {e}")
        # traceback.print_exc()

def decrypt_file(file_path, key):
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {path}")
        return
    
    try:
        with open(path, "rb") as f:
            file_content = f.read()
        
        # Read header length
        if len(file_content) < 4:
            print("Invalid file format (too short for header len)")
            return
            
        header_len = struct.unpack("I", file_content[:4])[0]
        
        # Read header
        header_end = 4 + header_len
        if len(file_content) < header_end:
             print("Invalid file format (truncated header)")
             return
             
        header_bytes = file_content[4:header_end]
        try:
            header = json.loads(header_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            # Fallback for old format or corrupt files could be added here, 
            # but for now we assume new format.
            print("Failed to decode metadata header. File might be in old format or corrupted.")
            return

        # Read Nonce and Ciphertext
        nonce_end = header_end + 12
        if len(file_content) < nonce_end:
            print("Invalid file format (truncated nonce)")
            return

        nonce = file_content[header_end:nonce_end]
        ciphertext = file_content[nonce_end:]

        # Decrypt
        aesgcm = AESGCM(key)
        original_data = aesgcm.decrypt(nonce, ciphertext, None)

        # Restore
        ext = header.get("ext", "")
        # Fallback if ext is missing? Use .txt? Or try to keep current extension? 
        # But for strictly restoring, we accept the header.
        
        restore_path = path.with_name(path.stem + ext)
        
        with open(restore_path, "wb") as f:
            f.write(original_data)
        
        # Restore Metadata
        if "mtime" in header:
            os.utime(restore_path, (header["mtime"], header["mtime"]))
        if "mode" in header:
            os.chmod(restore_path, header["mode"])
        
        os.remove(path)
        print(f"Decrypted: {path} -> {restore_path}")
    except Exception as e:
        print(f"Failed to decrypt {path}: {e}")

def main():
    import sys
    
    # Custom argument parsing to handle "smart" mode
    # Usage 1: drtencrypt action target
    # Usage 2: drtencrypt target (smart mode)
    
    args_action = None
    args_target = None
    
    if len(sys.argv) == 2:
        # One argument: treated as target
        args_target = sys.argv[1]
    elif len(sys.argv) == 3:
        # Two arguments: action target
        if sys.argv[1] in ["encrypt", "decrypt"]:
            args_action = sys.argv[1]
            args_target = sys.argv[2]
        else:
            print("Invalid usage. Usage: drtencrypt [encrypt|decrypt] <target> OR drtencrypt <target>")
            exit(1)
    else:
        # Let argparse handle help/errors for 0 or >2 args
        parser = argparse.ArgumentParser(description="DRT Global Encryptor (AES-256-GCM)")
        parser.add_argument("action", choices=["encrypt", "decrypt"], nargs="?", help="Action to perform (optional)")
        parser.add_argument("target", help="File or directory to process")
        parser.parse_args() # This will likely exit/print help
        return

    key = load_key()
    
    target_path = Path(args_target).resolve()
    
    # Smart mode detection
    if args_action is None:
        if target_path.is_dir():
            print("Smart mode for directories is ambiguous. Please specify 'encrypt' or 'decrypt'.")
            exit(1)
        
        if target_path.suffix == ".drt":
            args_action = "decrypt"
            print(f"Auto-detected .drt file. Decrypting {target_path.name}...")
        else:
            args_action = "encrypt"
            print(f"Auto-detected normal file. Encrypting {target_path.name}...")

    targets = []
    if target_path.is_dir():
        for root, _, files in os.walk(target_path):
            for file in files:
                filepath = Path(root) / file
                if args_action == "encrypt":
                    if filepath.suffix == ".drt":
                        continue
                    if filepath.name == "drt_encryptor.py":
                        continue
                if args_action == "decrypt" and filepath.suffix != ".drt":
                    continue
                targets.append(filepath)
    else:
        targets.append(target_path)

    print(f"Processing {len(targets)} files...")
    for target in targets:
        if args_action == "encrypt":
            encrypt_file(target, key)
        elif args_action == "decrypt":
            decrypt_file(target, key)

if __name__ == "__main__":
    main()
