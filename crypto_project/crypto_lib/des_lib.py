from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

KEY = b'12345678'  # 8 byte

def encrypt_des(message: bytes):
    cipher = DES.new(KEY, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, DES.block_size))
    return cipher.iv + ciphertext

def decrypt_des(ciphertext: bytes):
    iv = ciphertext[:8]
    data = ciphertext[8:]
    cipher = DES.new(KEY, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), DES.block_size)
