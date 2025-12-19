SBOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
]

def substitute(nibble):
    return SBOX[nibble]

def encrypt_simple_aes(byte):
    high = substitute(byte >> 4)
    low = substitute(byte & 0x0F)
    return (high << 4) | low

def decrypt_simple_aes(byte):
    inv = [SBOX.index(i) for i in range(16)]
    high = inv[byte >> 4]
    low = inv[byte & 0x0F]
    return (high << 4) | low
