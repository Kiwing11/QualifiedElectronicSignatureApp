from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib
import os

def generate_rsa_keys():
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_aes(data, pin):
    key = hashlib.sha256(pin.encode()).digest()  # Use SHA-256 over our key to get a proper-sized AES key
    cipher = AES.new(key, AES.MODE_CBC)  # Use CBC mode
    padded_data = pad(data, AES.block_size)  # Pad the data to be a multiple of the block size
    ciphertext = cipher.encrypt(padded_data)
    return cipher.iv, ciphertext

def save_keys(private_key, public_key):
    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)

