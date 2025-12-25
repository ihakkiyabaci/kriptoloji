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

HOST = "127.0.0.1"
PORT = 5000

# ---------------- SOCKET ----------------
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# ---------------- ECC ----------------
client_key = ECC.generate(curve="P-256")
client_public_key = client_key.public_key()

client_public_pem = client_public_key.export_key(format="PEM")
client_public_pem_bytes = client_public_pem.encode()

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

# ---------------- SERVER DİNLE ----------------
def listen_server():
    global shared_aes_key

    # SERVER ECC KEY
    header = recv_line(client)
    if header == "ECC_SERVER_KEY":
        pem = b""
        while b"END_KEY" not in pem:
            pem += client.recv(1024)

        server_public_pem = pem.replace(b"END_KEY\n", b"").decode()
        server_public = ECC.import_key(server_public_pem)

        ecc_log.insert(tk.END, "[SERVER ECC PUBLIC KEY]\n")
        ecc_log.insert(tk.END, server_public_pem + "\n")

        # ECDH
        shared_point = server_public.pointQ * client_key.d
        secret = int(shared_point.x).to_bytes(32, "big")
        shared_aes_key = HKDF(secret, 16, b"", SHA256)

        ecc_log.insert(tk.END, "[ECC SHARED AES KEY]\n")
        ecc_log.insert(tk.END, shared_aes_key.hex() + "\n\n")

    # NORMAL MESAJLAR
    while True:
        try:
            algo = recv_line(client)
            length = int(recv_line(client))
            encrypted = recv_exact(client, length)

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

            chat_log.insert(tk.END, "[SERVER]\n")
            chat_log.insert(tk.END, f"Algoritma: {algo}\n")
            chat_log.insert(tk.END, f"Şifreli (HEX): {encrypted_hex}\n")
            chat_log.insert(tk.END, f"Mesaj (Plain): {plain.decode()}\n\n")
            chat_log.see(tk.END)

        except:
            break

# ---------------- MESAJ GÖNDER ----------------
def send_message():
    msg = msg_entry.get().encode()
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
        if shared_aes_key is None:
            chat_log.insert(tk.END, "⚠ ECC anahtar hazır değil\n\n")
            return
        enc = encrypt_with_ecc_aes(msg, shared_aes_key)
    else:
        return

    encrypted_hex = binascii.hexlify(enc).decode()

    client.sendall((algo + "\n").encode())
    client.sendall((str(len(enc)) + "\n").encode())
    client.sendall(enc)

    chat_log.insert(tk.END, "[CLIENT]\n")
    chat_log.insert(tk.END, f"Algoritma: {algo}\n")
    chat_log.insert(tk.END, f"Şifreli (HEX): {encrypted_hex}\n")
    chat_log.insert(tk.END, f"Mesaj (Plain): {msg.decode()}\n\n")
    chat_log.see(tk.END)

    msg_entry.delete(0, tk.END)

# ---------------- GUI ----------------
root = tk.Tk()
root.title("CLIENT CHAT")

chat_log = tk.Text(root, width=80, height=18)
chat_log.pack(padx=10, pady=5)

ecc_log = tk.Text(root, width=80, height=12)
ecc_log.pack(padx=10, pady=5)

ecc_log.insert(tk.END, "[CLIENT ECC PUBLIC KEY]\n")
ecc_log.insert(tk.END, client_public_pem + "\n\n")

msg_entry = tk.Entry(root, width=70)
msg_entry.pack(pady=5)

algo_var = tk.StringVar(value="AES")
for a in ["AES", "DES", "RSA", "MANUAL", "ECC"]:
    tk.Radiobutton(root, text=a, variable=algo_var, value=a).pack(anchor="w")

tk.Button(root, text="Gönder", command=send_message).pack(pady=5)

# CLIENT ECC KEY GÖNDER
client.sendall(b"ECC_CLIENT_KEY\n")
client.sendall(client_public_pem_bytes)
client.sendall(b"\nEND_KEY\n")

threading.Thread(target=listen_server, daemon=True).start()
root.mainloop()
