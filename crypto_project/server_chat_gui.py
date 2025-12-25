import socket
import threading
import tkinter as tk
import binascii

from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

from crypto_lib.aes_lib import encrypt_aes, decrypt_aes
from crypto_lib.des_lib import encrypt_des, decrypt_des
from crypto_lib.rsa_lib import encrypt_rsa, decrypt_rsa
from crypto_lib.ecc_lib import encrypt_with_ecc_aes, decrypt_with_ecc_aes
from crypto_manual.simple_aes import encrypt_simple_aes, decrypt_simple_aes

HOST = "0.0.0.0"
PORT = 5000

conn = None
shared_aes_key = None

# ---------------- TCP ----------------
def recv_line(c):
    data = b""
    while not data.endswith(b"\n"):
        data += c.recv(1)
    return data.decode().strip()

def recv_exact(c, n):
    data = b""
    while len(data) < n:
        data += c.recv(n - len(data))
    return data

# ---------------- CLIENT ----------------
def handle_client():
    global conn, shared_aes_key

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)

    log.insert(tk.END, "Sunucu dinlemede...\n")
    conn, addr = server.accept()
    log.insert(tk.END, f"Bağlanan: {addr}\n\n")

    # ECC SERVER KEY
    server_key = ECC.generate(curve="P-256")
    server_public = server_key.public_key()
    server_public_pem = server_public.export_key(format="PEM")

    ecc_log.insert(tk.END, "[SERVER ECC PUBLIC KEY]\n")
    ecc_log.insert(tk.END, server_public_pem + "\n\n")

    conn.sendall(b"ECC_SERVER_KEY\n")
    conn.sendall(server_public_pem.encode())
    conn.sendall(b"\nEND_KEY\n")

    # CLIENT KEY
    header = recv_line(conn)
    if header == "ECC_CLIENT_KEY":
        pem = b""
        while b"END_KEY" not in pem:
            pem += conn.recv(1024)

        client_public_pem = pem.replace(b"END_KEY\n", b"").decode()
        client_public = ECC.import_key(client_public_pem)

        shared_point = client_public.pointQ * server_key.d
        secret = int(shared_point.x).to_bytes(32, "big")
        shared_aes_key = HKDF(secret, 16, b"", SHA256)

        ecc_log.insert(tk.END, "[ECC SHARED AES KEY]\n")
        ecc_log.insert(tk.END, shared_aes_key.hex() + "\n\n")

    # CLIENT MESAJLARI
    while True:
        algo = recv_line(conn)
        length = int(recv_line(conn))
        encrypted = recv_exact(conn, length)

        encrypted_hex = binascii.hexlify(encrypted).decode()

        if algo == "AES":
            plain = decrypt_aes(encrypted)
        elif algo == "DES":
            plain = decrypt_des(encrypted)
        elif algo == "RSA":
            plain = decrypt_rsa(encrypted)
        elif algo == "MANUAL":
            plain = bytes([decrypt_simple_aes(b) for b in encrypted])
        elif algo == "ECC":
            plain = decrypt_with_ecc_aes(encrypted, shared_aes_key)
        else:
            plain = b"?"

        log.insert(tk.END, "[CLIENT]\n")
        log.insert(tk.END, f"Algoritma: {algo}\n")
        log.insert(tk.END, f"Şifreli (HEX): {encrypted_hex}\n")
        log.insert(tk.END, f"Mesaj (Plain): {plain.decode()}\n\n")

# ---------------- SERVER MESAJ GÖNDER ----------------
def send_reply():
    msg = reply_entry.get().encode()
    algo = algo_var.get()

    if algo == "AES":
        enc = encrypt_aes(msg)
    elif algo == "DES":
        enc = encrypt_des(msg)
    elif algo == "RSA":
        enc = encrypt_rsa(msg)
    elif algo == "MANUAL":
        enc = bytes([encrypt_simple_aes(b) for b in msg])
    elif algo == "ECC":
        enc = encrypt_with_ecc_aes(msg, shared_aes_key)
    else:
        return

    encrypted_hex = binascii.hexlify(enc).decode()

    conn.sendall((algo + "\n").encode())
    conn.sendall((str(len(enc)) + "\n").encode())
    conn.sendall(enc)

    log.insert(tk.END, "[SERVER]\n")
    log.insert(tk.END, f"Algoritma: {algo}\n")
    log.insert(tk.END, f"Şifreli (HEX): {encrypted_hex}\n")
    log.insert(tk.END, f"Mesaj (Plain): {msg.decode()}\n\n")

# ---------------- GUI ----------------
root = tk.Tk()
root.title("SERVER CHAT")

log = tk.Text(root, width=80, height=18)
log.pack(padx=10, pady=5)

ecc_log = tk.Text(root, width=80, height=10)
ecc_log.pack(padx=10, pady=5)

reply_entry = tk.Entry(root, width=60)
reply_entry.pack(pady=5)

algo_var = tk.StringVar(value="AES")
for a in ["AES", "DES", "RSA", "MANUAL", "ECC"]:
    tk.Radiobutton(root, text=a, variable=algo_var, value=a).pack(anchor="w")

tk.Button(root, text="Cevap Gönder", command=send_reply).pack(pady=5)
tk.Button(
    root,
    text="Sunucuyu Başlat",
    command=lambda: threading.Thread(target=handle_client, daemon=True).start()
).pack(pady=5)

root.mainloop()
