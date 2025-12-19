import socket
import threading
import tkinter as tk
import binascii

from crypto_lib.aes_lib import encrypt_aes, decrypt_aes
from crypto_lib.des_lib import encrypt_des, decrypt_des
from crypto_lib.rsa_lib import encrypt_rsa, decrypt_rsa
from crypto_manual.simple_aes import encrypt_simple_aes, decrypt_simple_aes

HOST = "127.0.0.1"
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# ---------------- TCP yardımcı fonksiyonlar ----------------

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

# ---------------- Server'dan mesaj dinleme ----------------

def listen_server():
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
            else:
                plain = b"?"

            chat_log.insert(tk.END, f"[SERVER]\n")
            chat_log.insert(tk.END, f"Algoritma: {algo}\n")
            chat_log.insert(tk.END, f"Şifreli (HEX): {encrypted_hex}\n")
            chat_log.insert(tk.END, f"Mesaj: {plain.decode()}\n\n")
            chat_log.see(tk.END)

        except:
            break

# ---------------- Mesaj gönderme ----------------

def send_message():
    msg = msg_entry.get().encode()
    if not msg:
        return

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

    client.sendall((algo + "\n").encode())
    client.sendall((str(len(enc)) + "\n").encode())
    client.sendall(enc)

    chat_log.insert(tk.END, f"[CLIENT]\n")
    chat_log.insert(tk.END, f"Algoritma: {algo}\n")
    chat_log.insert(tk.END, f"Şifreli (HEX): {encrypted_hex}\n")
    chat_log.insert(tk.END, f"Gönderilen: {msg.decode()}\n\n")
    chat_log.see(tk.END)

    msg_entry.delete(0, tk.END)  # 🔥 önemli

# ---------------- GUI ----------------

root = tk.Tk()
root.title("CLIENT CHAT")

chat_log = tk.Text(root, width=80, height=22)
chat_log.pack(padx=10, pady=5)

msg_entry = tk.Entry(root, width=70)
msg_entry.pack(pady=5)

algo_var = tk.StringVar(value="AES")

algo_frame = tk.Frame(root)
algo_frame.pack(pady=3)

for a in ["AES", "DES", "RSA", "MANUAL"]:
    tk.Radiobutton(algo_frame, text=a, variable=algo_var, value=a).pack(side=tk.LEFT, padx=5)

send_btn = tk.Button(root, text="Gönder", width=20, command=send_message)
send_btn.pack(pady=8)

# 🔥 Thread'i EN SON başlat
threading.Thread(target=listen_server, daemon=True).start()

root.mainloop()
