from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
public_key = key.publickey()

def encrypt_rsa(message: bytes):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message)

def decrypt_rsa(ciphertext: bytes):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext)
