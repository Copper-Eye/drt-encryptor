import os
import struct
import json
import argparse
import sys
import wave
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from PIL import Image

KEY_DIR = Path.home() / ".drtencryptor"
KEY_FILE = KEY_DIR / "secret.key"

# --- EXISTING AES GCM LOGIC ---

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
            sys.exit(1)
    else:
        try:
            with open(KEY_FILE, "rb") as f:
                key = f.read()
            if len(key) != 32:
                print(f"Warning: Existing key at {KEY_FILE} is not 32 bytes (256-bit). It might be an old key.")
        except Exception as e:
            print(f"Error loading key: {e}")
            sys.exit(1)
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

# --- RSA & STEGANOGRAPHY LOGIC ---

def generate_rsa_keys(output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    priv_path = output_dir / "private_key.pem"
    pub_path = output_dir / "public_key.pem"

    # Save Private Key
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save Public Key
    public_key = private_key.public_key()
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
    print(f"Generated RSA Keypair:\nPrivate: {priv_path}\nPublic: {pub_path}")

def encrypt_rsa_message(message, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
        
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Return as base64 for easy reading/transport
    import base64
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_rsa_message(ciphertext_b64, private_key_bytes):
    # private_key_bytes can be loaded from file or extracted from image
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
    )
    
    import base64
    ciphertext = base64.b64decode(ciphertext_b64)
    
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

# --- HYBRID ENCRYPTION (AES + RSA) ---

def hybrid_encrypt(file_path, public_key_path):
    """Encrypts a file with a random AES key, then encrypts that key with RSA."""
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {path}")
        return

    try:
        # 1. Generate Ephemeral AES Key
        aes_key = AESGCM.generate_key(bit_length=256)
        
        # 2. Encrypt File Content with AES Key
        with open(path, "rb") as f:
            data = f.read()
            
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # 3. Encrypt AES Key with RSA Public Key
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
            
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 4. Package (Len(Key) + Key + Nonce + Content)
        # RSA 2048 key -> 256 bytes encrypted output
        # But we store length just in case
        key_len = len(encrypted_aes_key)
        
        final_data = struct.pack(">I", key_len) + encrypted_aes_key + nonce + ciphertext
        
        new_path = path.with_name(path.name + ".drt-rsa")
        with open(new_path, "wb") as f:
            f.write(final_data)
            
        print(f"Hybrid Encrypted: {path} -> {new_path}")
        
    except Exception as e:
        print(f"Error encrypting file: {e}")

def hybrid_decrypt(file_path, private_key_path):
    """Decrypts a hybrid encrypted file using the Private Key."""
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {path}")
        return
        
    try:
        with open(path, "rb") as f:
            file_content = f.read()
            
        # 1. Read Encrypted Key Length
        if len(file_content) < 4:
            print("Invalid format.")
            return
            
        key_len = struct.unpack(">I", file_content[:4])[0]
        
        # 2. Read Encrypted AES Key
        key_end = 4 + key_len
        if len(file_content) < key_end:
            print("Invalid format (truncated key).")
            return
            
        encrypted_aes_key = file_content[4:key_end]
        
        # 3. Read Nonce (12 bytes)
        nonce_end = key_end + 12
        if len(file_content) < nonce_end:
            print("Invalid format (truncated nonce).")
            return
            
        nonce = file_content[key_end:nonce_end]
        ciphertext = file_content[nonce_end:]
        
        # 4. Decrypt AES Key with RSA Private Key
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
            
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 5. Decrypt Content
        aesgcm = AESGCM(aes_key)
        original_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Restore (remove .drt-rsa suffix)
        if path.suffix == ".drt-rsa":
            restore_path = path.with_suffix("")
        else:
            restore_path = path.with_name("decrypted_" + path.name)

        with open(restore_path, "wb") as f:
            f.write(original_data)
            
        print(f"Decrypted: {restore_path}")
        
    except Exception as e:
        print(f"Failed to decrypt: {e}")

def stego_hide_file(image_path, file_to_hide, output_image_path):
    """Hide the content of file_to_hide inside image_path using LSB."""
    
    # 1. Read the secret file
    with open(file_to_hide, "rb") as f:
        secret_data = f.read()
    
    # Prepend size of data (4 bytes unsigned int, Big Endian)
    payload = struct.pack(">I", len(secret_data)) + secret_data
    
    # Convert payload to bits
    bits = []
    for byte in payload:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
            
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
        
    width, height = img.size
    pixels = img.load()
    
    if len(bits) > width * height * 3:
        print("Error: Image not large enough to hide this file.")
        return

    idx = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            
            # Modify LSB of Red
            if idx < len(bits):
                r = (r & ~1) | bits[idx]
                idx += 1
            # Modify LSB of Green
            if idx < len(bits):
                g = (g & ~1) | bits[idx]
                idx += 1
            # Modify LSB of Blue
            if idx < len(bits):
                b = (b & ~1) | bits[idx]
                idx += 1
                
            pixels[x, y] = (r, g, b)
            if idx >= len(bits):
                break
        if idx >= len(bits):
            break
            
    img.save(output_image_path)
    print(f"Hidden {file_to_hide} inside {output_image_path}")

def stego_extract_file(image_path):
    """Extract hidden file content from image."""
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
        
    width, height = img.size
    pixels = img.load()
    
    bits = []
    # Read LSBs
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)
            
    # Read length (first 32 bits = 4 bytes)
    # We need at least 32 bits
    if len(bits) < 32:
         return None
         
    length_bits = bits[:32]
    length_val = 0
    for bit in length_bits:
        length_val = (length_val << 1) | bit
        
    # Read the data
    data_bits = bits[32 : 32 + (length_val * 8)]
    
    data_bytes = bytearray()
    current_byte = 0
    bit_count = 0
    
    for bit in data_bits:
        current_byte = (current_byte << 1) | bit
        bit_count += 1
        if bit_count == 8:
            data_bytes.append(current_byte)
            current_byte = 0
            bit_count = 0
            
    return bytes(data_bytes)

def stego_hide_audio(audio_path, file_to_hide, output_audio_path):
    """Hide the content of file_to_hide inside audio_path (WAV) using LSB."""
    
    # 1. Read secret file
    with open(file_to_hide, "rb") as f:
        secret_data = f.read()
    
    # Prepend size (4 bytes unsigned int, Big Endian)
    payload = struct.pack(">I", len(secret_data)) + secret_data
    
    # Convert payload to bits
    bits = []
    for byte in payload:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)

    # 2. Open Audio
    try:
        with wave.open(audio_path, 'rb') as song:
            params = song.getparams()
            n_frames = song.getnframes()
            frames = song.readframes(n_frames)
    except wave.Error as e:
        print(f"Error reading WAV file: {e}")
        return

    frame_bytes = bytearray(frames)
    
    if len(bits) > len(frame_bytes):
        print("Error: Audio file is not large enough to hold this secret.")
        return
        
    # 3. Modify LSBs
    for i, bit in enumerate(bits):
        frame_bytes[i] = (frame_bytes[i] & 254) | bit
        
    # 4. Write output
    try:
        with wave.open(output_audio_path, 'wb') as fd:
            fd.setparams(params)
            fd.writeframes(frame_bytes)
        print(f"Hidden {file_to_hide} inside {output_audio_path} (Audio)")
    except wave.Error as e:
        print(f"Error writing WAV file: {e}")

def stego_extract_audio(audio_path):
    """Extract hidden file content from WAV audio."""
    try:
        with wave.open(audio_path, 'rb') as song:
            frames = song.readframes(song.getnframes())
    except wave.Error as e:
        print(f"Error reading WAV file: {e}")
        return None

    frame_bytes = bytearray(frames)
    
    # Extract bits from LSBs
    # We don't know the length yet, but we need at least 32 bits for the length header
    if len(frame_bytes) < 32:
        return None
        
    # Read length (first 32 bits/frames)
    length_val = 0
    for i in range(32):
        length_val = (length_val << 1) | (frame_bytes[i] & 1)
        
    total_bits_needed = 32 + (length_val * 8)
    if len(frame_bytes) < total_bits_needed:
        # Corrupt or not enough data
        return None
        
    data_bytes = bytearray()
    current_byte = 0
    bit_count = 0
    
    # Start reading after the 32 header bits
    for i in range(32, total_bits_needed):
        bit = frame_bytes[i] & 1
        current_byte = (current_byte << 1) | bit
        bit_count += 1
        
        if bit_count == 8:
            data_bytes.append(current_byte)
            current_byte = 0
            bit_count = 0
            
    return bytes(data_bytes)

def stego_hide_wrapper(source, secret, output):
    ext = Path(source).suffix.lower()
    if ext == '.wav':
        stego_hide_audio(source, secret, output)
    else:
        # Default to image
        stego_hide_file(source, secret, output)

def stego_extract_wrapper(source):
    ext = Path(source).suffix.lower()
    if ext == '.wav':
        return stego_extract_audio(source)
    else:
        return stego_extract_file(source)


def print_explanation():
    print("""
=== Educational: How Public/Private RSA Keys Work ===

1. **The Key Pair**: 
   - Imagine a mailbox with a lock (Public Key) and a key that opens it (Private Key).
   - The **Public Key** is shared with everyone. You give it to your friends.
   - The **Private Key** is kept secret. Only you have it.

2. **Encryption (Locking)**:
   - When someone wants to send you a secret message, they use your **Public Key** to "lock" the message.
   - Once locked, not even they can unlock it. It's scrambled math that only one number can solve.

3. **Decryption (Unlocking)**:
   - You receive the locked message.
   - You use your **Private Key** to "unlock" (decrypt) it.
   - Because the keys are mathematically linked (using prime numbers), only your specific private key works.

4. **Steganography (Hiding)**:
   - This tool also allows you to HIDE your Private Key inside an image file without changing how the image looks.
   - It tweaks the very last bit of the color values (LSB).
   - You can send the image to yourself or store it safely, and later "extract" the key to read your messages.
""")

# --- MAIN CLI ---

def main():
    parser = argparse.ArgumentParser(description="DRT Global Encryptor & RSA/Stego Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # AES Logic
    parser_enc = subparsers.add_parser("encrypt", help="Encrypt a file/directory (AES)")
    parser_enc.add_argument("target", help="File or directory")
    
    parser_dec = subparsers.add_parser("decrypt", help="Decrypt a file/directory (AES)")
    parser_dec.add_argument("target", help="File or directory")

    # RSA Logic
    parser_rsagen = subparsers.add_parser("rsa-gen", help="Generate RSA Key Pair")
    parser_rsagen.add_argument("--out", default=".", help="Output directory")

    parser_rsaenc = subparsers.add_parser("rsa-encrypt", help="Encrypt a message with Public Key")
    parser_rsaenc.add_argument("public_key", help="Path to Public Key PEM")
    parser_rsaenc.add_argument("message", help="Message text to encrypt")

    parser_stegohide = subparsers.add_parser("stego-hide", help="Hide a file in an image or audio (WAV)")
    parser_stegohide.add_argument("source", help="Source image/audio path")
    parser_stegohide.add_argument("secret", help="File to hide")
    parser_stegohide.add_argument("output", help="Output path")

    parser_stegounlock = subparsers.add_parser("stego-unlock", help="Extract key from file and decrypt message")
    parser_stegounlock.add_argument("source", help="File containing the hidden Private Key (Image/Audio)")
    parser_stegounlock.add_argument("ciphertext", help="Encrypted message (Base64 string)")

    # Hybrid Logic
    parser_send = subparsers.add_parser("send-to", help="Encrypt a FILE for a recipient (Hybrid AES+RSA)")
    parser_send.add_argument("file", help="File to encrypt")
    parser_send.add_argument("public_key", help="Recipient's Public Key")

    parser_receive = subparsers.add_parser("receive", help="Decrypt a FILE sent to you (Hybrid AES+RSA)")
    parser_receive.add_argument("file", help="Encrypted file (.drt-rsa)")
    parser_receive.add_argument("private_key", help="Your Private Key")

    # Educational
    subparsers.add_parser("explain", help="Explain how this works")

    # Fallback/Smart mode handling
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    # Handle older "smart" syntax: drtencryptor file
    # If the first arg is not a command, treat it as a target for old behavior
    if sys.argv[1] not in ["encrypt", "decrypt", "rsa-gen", "rsa-encrypt", "stego-hide", "stego-unlock", "explain", "send-to", "receive", "-h", "--help"]:
        # Legacy Smart Mode
        target_path = Path(sys.argv[1]).resolve()
        key = load_key()
        if target_path.suffix == ".drt":
            print(f"Auto-detected .drt file. Decrypting {target_path.name}...")
            decrypt_file(target_path, key)
        else:
            print(f"Auto-detected normal file. Encrypting {target_path.name}...")
            encrypt_file(target_path, key)
        return

    args = parser.parse_args()

    if args.command == "encrypt":
        key = load_key()
        target = Path(args.target)
        if target.is_dir():
            print("Encrypting dir...")
            # Naive recursion
            for root, _, files in os.walk(target):
                for f in files:
                    fp = Path(root) / f
                    if fp.suffix != '.drt' and fp.name != 'drt_encryptor.py':
                        encrypt_file(fp, key)
        else:
            encrypt_file(target, key)

    elif args.command == "decrypt":
        key = load_key()
        target = Path(args.target)
        if target.is_dir():
            print("Decrypting dir...")
            for root, _, files in os.walk(target):
                for f in files:
                    fp = Path(root) / f
                    if fp.suffix == '.drt':
                        decrypt_file(fp, key)
        else:
            decrypt_file(target, key)

    elif args.command == "rsa-gen":
        generate_rsa_keys(args.out)

    elif args.command == "rsa-encrypt":
        enc = encrypt_rsa_message(args.message, args.public_key)
        print(f"--- Encrypted Message (Base64) ---\n{enc}\n------------------------------------")

    elif args.command == "stego-hide":
        stego_hide_wrapper(args.source, args.secret, args.output)

    elif args.command == "stego-unlock":
        priv_key_bytes = stego_extract_wrapper(args.source)
        if not priv_key_bytes:
            print("No hidden key found or extraction failed.")
            return
        try:
            msg = decrypt_rsa_message(args.ciphertext, priv_key_bytes)
            print(f"--- Decrypted Message ---\n{msg}\n-------------------------")
        except Exception as e:
            print(f"Failed to decrypt message (Wrong key?): {e}")

    elif args.command == "explain":
        print_explanation()

    elif args.command == "send-to":
        hybrid_encrypt(args.file, args.public_key)

    elif args.command == "receive":
        hybrid_decrypt(args.file, args.private_key)

if __name__ == "__main__":
    main()
