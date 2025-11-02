#!/usr/bin/env python3
"""
CLI helper tool for sharepass API usage.

This script provides encryption functionality to use sharepass as a CLI tool.
"""

import os
import json
import base64
import sys
import argparse

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_secret(secret: str, key: str) -> str:
    """
    Encrypt a secret using AES-GCM with PBKDF2 key derivation.
    Matches the encryption format used by the web interface.
    
    Args:
        secret: The plaintext secret to encrypt
        key: The encryption key/password
        
    Returns:
        JSON string containing encrypted data (salt, iv, ciphertext)
    """
    # Generate random salt and IV
    salt = os.urandom(16)
    iv = os.urandom(12)
    
    # Derive AES key from password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    aes_key = kdf.derive(key.encode())
    
    # Encrypt the secret
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, secret.encode(), None)
    
    # Encode as base64 and return as JSON
    encrypted_data = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    
    return json.dumps(encrypted_data)


def main():
    parser = argparse.ArgumentParser(
        description="CLI helper for sharepass API - encrypt secrets for curl usage"
    )
    parser.add_argument(
        "secret",
        help="The secret text to encrypt (or '-' to read from stdin)",
        nargs="?",
        default=None,
    )
    parser.add_argument(
        "-k", "--key", required=True, help="Encryption key/password"
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "curl"],
        default="json",
        help="Output format: 'json' for encrypted data only, 'curl' for full curl command",
    )
    parser.add_argument(
        "-u",
        "--url",
        default="http://localhost:8080",
        help="Base URL of the sharepass server (default: http://localhost:8080)",
    )
    
    args = parser.parse_args()
    
    # Read secret from stdin if '-' or not provided
    if args.secret == "-" or args.secret is None:
        secret = sys.stdin.read().rstrip("\n")
    else:
        secret = args.secret
    
    if not secret:
        print("Error: Secret cannot be empty", file=sys.stderr)
        sys.exit(1)
    
    # Encrypt the secret
    try:
        encrypted_data = encrypt_secret(secret, args.key)
    except Exception as e:
        print(f"Error encrypting secret: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Output based on format
    if args.output == "json":
        print(encrypted_data)
    elif args.output == "curl":
        # Create a curl command example
        json_payload = json.dumps({"encrypted_secret": encrypted_data})
        escaped_payload = json_payload.replace("'", "'\\''")
        print(f"# Encrypt and create secret:")
        print(f"curl -X POST {args.url}/api/lock \\")
        print(f"  -H 'Content-Type: application/json' \\")
        print(f"  -d '{json_payload}'")
        print()
        print("# To retrieve the secret:")
        print("# curl -X POST http://localhost:8080/api/unlock \\")
        print("#   -H 'Content-Type: application/json' \\")
        print("#   -d '{\"download_code\": \"<CODE>\", \"key\": \"<KEY>\"}'")


if __name__ == "__main__":
    main()

