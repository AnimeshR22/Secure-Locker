import os
import sys
import json
import time
import argparse
import base64

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.authentication.password_auth import (
    validate_password_strength,
    hash_password,
    verify_password
)

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

META_EXT = ".meta.json"
ENC_EXT = ".protected"

def derive_key(password: str, salt: bytes) -> bytes:
    # Derive a 256-bit key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def protect_file(args):
    pwd = None
    if args.method == "manual":
        pwd = input("Enter a strong password: ")
        ok, issues = validate_password_strength(pwd)
        if not ok:
            print("Password validation failed:")
            for issue in issues:
                print(" -", issue)
            sys.exit(1)
    else:
        print("Only manual method supported for encryption in this prototype.")
        sys.exit(1)

    infile = args.file
    if not os.path.isfile(infile):
        print(f"File not found: {infile}")
        sys.exit(1)
    with open(infile, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    key = derive_key(pwd, salt)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)

    ct = aesgcm.encrypt(iv, data, None)

    basename = os.path.basename(infile)
    out_protected = basename + ENC_EXT
    with open(out_protected, 'wb') as outf:
        outf.write(ct)

    pwd_hash = hash_password(pwd)
    metadata = {
        "method": args.method,
        "password_hash": pwd_hash,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "timestamp": int(time.time()),
        "original_filename": basename
    }
    out_meta = basename + META_EXT
    with open(out_meta, "w") as meta_f:
        json.dump(metadata, meta_f, indent=2)

    print(f"Encrypted file: {out_protected}")
    print(f"Metadata written to: {out_meta}")

def decrypt_file(args):
    meta_path = args.meta
    if not os.path.isfile(meta_path):
        print(f"Metadata file not found: {meta_path}")
        sys.exit(1)
    with open(meta_path, 'r') as mf:
        metadata = json.load(mf)

    pwd = input("Enter password to decrypt: ")
    if not verify_password(metadata['password_hash'], pwd):
        print("Password verification failed.")
        sys.exit(1)

    enc_file = metadata['original_filename'] + ENC_EXT
    if not os.path.isfile(enc_file):
        print(f"Encrypted file not found: {enc_file}")
        sys.exit(1)
    with open(enc_file, 'rb') as ef:
        ct = ef.read()

    salt = base64.b64decode(metadata['salt'])
    iv = base64.b64decode(metadata['iv'])
    key = derive_key(pwd, salt)
    aesgcm = AESGCM(key)

    try:
        data = aesgcm.decrypt(iv, ct, None)
    except Exception as e:
        print("Decryption failed:", e)
        sys.exit(1)

    out_decrypted = metadata['original_filename'] + ".decrypted"
    with open(out_decrypted, 'wb') as df:
        df.write(data)

    print(f"Decrypted output written to: {out_decrypted}")

def main():
    parser = argparse.ArgumentParser(prog="secure_locker")
    sub = parser.add_subparsers(dest="command")

    p_protect = sub.add_parser("protect", help="Protect (encrypt) a file using a password")
    p_protect.add_argument("file", help="Path to the file to encrypt")
    p_protect.add_argument("--method", choices=["manual"], default="manual",
                           help="Password generation method (only manual supported)")

    p_decrypt = sub.add_parser("decrypt", help="Decrypt a protected file using its metadata")
    p_decrypt.add_argument("meta", help="Path to the .meta.json file")

    args = parser.parse_args()
    if args.command == "protect":
        protect_file(args)
    elif args.command == "decrypt":
        decrypt_file(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()