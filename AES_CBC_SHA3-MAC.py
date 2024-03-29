#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dependencies Install Notes:
"python3 -m pip install PyCryptodome" (Crypto import statement)
"python3 -m pip install PyCryptodomex" (Cryptodome statement)
"python3 -m pip install Cryptography" (Cryptography import)
"""

# Import statements
import sys
import string
import os
import cryptography
from Cryptodome.Hash import SHA3_256

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

# Global variables
letters = string.ascii_letters + " "

def main(args):
    print(f"This script encrypts your plaintext using the AES block cipher in CBC mode and also decrypts it for you as well. The supported characters are: {letters}.")
    
    cleartext = input_handler()
    
    print(f"Running the AES block cipher in CBC mode based on this text '{cleartext}'. Please wait...\n")

    cleartext_data = cleartext.encode('utf-8')
    
    key, iv_key = key_iv_Gen()
    
    ciphertext = encrypt(cleartext_data, key, iv_key)
    print(f"Raw ciphertext encrypted data (Hex): {ciphertext.hex()}")

    decrypted_plaintext = decrypt(iv_key, ciphertext, key).decode('utf-8')
    print(f"\nYour decrypted plaintext: {decrypted_plaintext}\n")

    del key, iv_key, cleartext_data, ciphertext, decrypted_plaintext
    print("AES block cipher in CBC mode with SHA3-MAC tags implementation complete.\n")
    
def input_handler():
    cleartext = input("\nEnter your cleartext here: ")
    if cleartext != "":
        if all(char in letters for char in cleartext):
            print(f"\nConfirming input: {cleartext}\n")
        else:
            print("\nInvalid input. Ending.\n")
            sys.exit()
    else:
        print("\nNo input detected. Please run again.\n")
        sys.exit()
    
    return cleartext

def key_iv_Gen():
    key_gen = get_random_bytes(32) # AES-256 key
    iv_gen = get_random_bytes(AES.block_size) # Saw that I can also use "AES.block_size" instead of 16, so changed it this time.
    
    return key_gen, iv_gen

def encrypt(plaintext, key, iv_key):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv_key)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        
        hash = SHA3_256.new()
        hash.update(ciphertext)
        mac_tag = hash.digest()

        ciphertext += mac_tag # MAC tag now added to ciphertext.
        
        return ciphertext
    
    except Exception as error:
        print(f"Encountered an error during encryption: {error}")
        sys.exit()

def decrypt(iv, ciphertext, key):
    try:
        mac_tag = ciphertext[-32:] # Separating part of ciphertext that's the MAC tag.
        ciphertext = ciphertext[:-32]

        hash = SHA3_256.new()
        hash.update(ciphertext)
        if hash.digest() != mac_tag:
            raise ValueError("MAC tag verification failed. Message has been tampered with.")

        print(f"MAC tag verification successful: {mac_tag.hex()} == {hash.digest().hex()}")
        #^ With a verified MAC tag, we now decrypt.

        decrypt_cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = unpad(decrypt_cipher.decrypt(ciphertext), AES.block_size)

        return plain_text
    
    except Exception as error:
        print(f"Encountered an error during decryption: {error}")
        sys.exit()

if __name__ == '__main__':
    main(sys.argv[1:])