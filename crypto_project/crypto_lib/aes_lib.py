from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'0123456789abcdef'  # 16 byte

def encrypt_aes(message: bytes):
    cipher = AES.new(KEY, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return cipher.iv + ciphertext

def decrypt_aes(ciphertext: bytes):
    iv = ciphertext[:16]
    data = ciphertext[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)
