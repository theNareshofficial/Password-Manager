#!/usr/bin/env python3

import os
import base64
import json
import secrets
import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Ansi color code
RED = '\033[31m'        # RED color
GREEN = '\033[32m'      # GREEN color
RESET = '\033[0m'       # RESET all color
BLINK = '\033[5m'       # Blink content

banner = f"""{GREEN}{BLINK}

+---------------------------------+
|  Command-Line Password Manager  |
+---------------------------------+
 {RESET}
            Author  : Naresh
            Github  : https://github.com/theNareshofficial
            Youtube : https://www.youtube.com/@nareshtechweb930

{RESET}{RED}
"""

print(banner)

# Function to create a new key based on a master password and salt
def generate_key(master_password, salt):
    # Derive a key from the master password using a key derivation function
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))
    return key

# Function to encrypt data
def encrypt(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8'))

# Function to decrypt data
def decrypt(data, key):
    f = Fernet(key)
    return f.decrypt(data).decode('utf-8')

# Function to store a new password
def store_password(filename, master_password, service, password):
    # Read the existing data
    data = {}
    salt = os.urandom(16)  # Generate a new salt for this file

    if os.path.exists(filename):
        with open(filename, 'r') as f:
            data = json.load(f)
            if "salt" in data:
                salt = base64.urlsafe_b64encode(base64.urlsafe_b64decode(data["salt"]))

    # Encrypt the password
    key = generate_key(master_password, salt)
    encrypted_password = encrypt(password, key)

    # Store it in the data dictionary
    data["salt"] = base64.urlsafe_b64encode(salt).decode("UTF-8")
    data[service] = encrypted_password.decode('utf-8')

    # Write back to the file
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

# Function to retrieve a password
def retrieve_password(filename, master_password, service):
    if not os.path.exists(filename):
        print("No password file found.")
        return

    # Read the existing data
    with open(filename, 'r') as f:
        data = json.load(f)

    if "salt" not in data or service not in data:
        print(f"No password stored for {service}")
        return

    # Decrypt the password
    salt = base64.urlsafe_b64decode(data["salt"])
    key = generate_key(master_password, salt)
    encrypted_password = data[service]
    decrypted_password = decrypt(encrypted_password, key)

    print(f"The password for {service} is: {decrypted_password}")

# Function to generate a strong password
def generate_password(length=12, include_special=True):
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if include_special:
        characters += "!@#$%^&*()_+-=[]{}|;:',.<>?/`~"

    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

# Main CLI function
def main():
    parser = argparse.ArgumentParser(description="Command-Line Password Manager")

    parser.add_argument('--operation', required=True, choices=['store', 'retrieve', 'generate'],
                        help='Operation to perform: store, retrieve, generate')

    parser.add_argument('--master_password', required=True, help='Master password for encryption/decryption')

    parser.add_argument('--service', help='Service for which to store/retrieve the password')

    parser.add_argument('--password', help='Password to store (for store operation)')

    parser.add_argument('--filename', default='passwords.json', help='File to store passwords')

    parser.add_argument('--length', type=int, default=12, help='Length for generated password (for generate operation)')

    parser.add_argument('--include_special', type=bool, default=True, help='Include special characters in generated password')

    args = parser.parse_args()

    if args.operation == 'store':
        if not args.service or not args.password:
            print("Service and password are required for storing.")
            return
        store_password(args.filename, args.master_password, args.service, args.password)
        print(f"Password for {args.service} stored successfully.")

    elif args.operation == 'retrieve':
        if not args.service:
            print("Service is required for retrieving.")
            return
        retrieve_password(args.filename, args.master_password, args.service)

    elif args.operation == 'generate':
        password = generate_password(length=args.length, include_special=args.include_special)
        print(f"Generated password: {password}")

if __name__ == '__main__':
    main()
