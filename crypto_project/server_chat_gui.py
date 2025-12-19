import socket
import threading
import tkinter as tk
from crypto_lib.aes_lib import decrypt_aes, encrypt_aes
from crypto_lib.des_lib import decrypt_des, encrypt_des
from crypto_lib.rsa_lib import decrypt_rsa, encrypt_rsa
from crypto_manual.simple_aes import decrypt_simple_aes, encrypt_simple_aes
import binascii

HOST = "0.0.0.0"
PORT = 5000

conn = None

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

def handle_client():
    global conn
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    log.insert(tk.END, "Sunucu dinlemede...\n")

    conn, addr = server.accept()
    log.insert(tk.END, f"Bağlanan: {addr}\n\n")

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
        else:
            plain = b"?"

        log.insert(tk.END, f"[CLIENT]\nAlgoritma: {algo}\n")
        log.insert(tk.END, f"Şifreli: {encrypted_hex}\n")
        log.insert(tk.END, f"Çözülmüş: {plain.decode()}\n\n")

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
    else:
        return

    encrypted_hex = binascii.hexlify(enc).decode()

    conn.sendall((algo + "\n").encode())
    conn.sendall((str(len(enc)) + "\n").encode())
    conn.sendall(enc)

    log.insert(tk.END, f"[SERVER]\nAlgoritma: {algo}\n")
    log.insert(tk.END, f"Şifreli: {encrypted_hex}\n")
    log.insert(tk.END, f"Gönderilen: {msg.decode()}\n\n")

def start_server():
    threading.Thread(target=handle_client, daemon=True).start()

# GUI
root = tk.Tk()
root.title("SERVER CHAT")

log = tk.Text(root, width=80, height=25)
log.pack(padx=10, pady=5)

reply_entry = tk.Entry(root, width=60)
reply_entry.pack(pady=3)

algo_var = tk.StringVar(value="AES")
for a in ["AES", "DES", "RSA", "MANUAL"]:
    tk.Radiobutton(root, text=a, variable=algo_var, value=a).pack(anchor="w")

tk.Button(root, text="Cevap Gönder", command=send_reply).pack(pady=5)
tk.Button(root, text="Sunucuyu Başlat", command=start_server).pack(pady=5)

root.mainloop()
