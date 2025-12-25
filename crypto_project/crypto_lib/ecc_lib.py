from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

# Sunucu tarafı ECC anahtarı
server_key = ECC.generate(curve='P-256')
server_public = server_key.public_key()

def generate_shared_key(client_public_key):
    # ECDH ortak sır
    shared_point = client_public_key.pointQ * server_key.d
    shared_secret = int(shared_point.x).to_bytes(32, 'big')

    # AES anahtarı türet
    return HKDF(shared_secret, 16, b'', SHA256)

def encrypt_with_ecc_aes(message: bytes, aes_key: bytes):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    cipher = AES.new(aes_key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(message, AES.block_size))

def decrypt_with_ecc_aes(ciphertext: bytes, aes_key: bytes):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    iv = ciphertext[:16]
    data = ciphertext[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)
