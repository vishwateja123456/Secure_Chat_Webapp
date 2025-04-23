import tkinter as tk
import sys, time
from socket import *
from threading import Thread
import secure_crypto as crypto

HOST = input('Enter host: ')
PORT = int(input('Enter port: '))
NAME = input('Enter your name: ')
BUFFER_SIZE = 4096
ADDRESS = (HOST, PORT)

CLIENT = socket(AF_INET, SOCK_STREAM)
CLIENT.connect(ADDRESS)

private_key, public_key = crypto.generate_dh_key_pair()
CLIENT.send(crypto.serialize_public_key(public_key))
peer_bytes = CLIENT.recv(BUFFER_SIZE)
peer_public_key = crypto.deserialize_public_key(peer_bytes)
shared_key = crypto.derive_shared_key(private_key, peer_public_key)

top = tk.Tk()
top.title("Entice - Client 1")

messages_frame = tk.Frame(top)
my_msg = tk.StringVar()
scrollbar = tk.Scrollbar(messages_frame)
msg_list = tk.Listbox(messages_frame, height=25, width=100, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
msg_list.pack(side=tk.LEFT, fill=tk.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tk.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", lambda event=None: send())
entry_field.pack()
send_button = tk.Button(top, text="Send", command=lambda: send())
send_button.pack()

def receive():
    msg_list.insert(tk.END, f" Welcome! {NAME}")
    msg_list.insert(tk.END, " You are online!")
    while True:
        try:
            data = CLIENT.recv(BUFFER_SIZE)
            if not data:
                break
            decrypted = crypto.decrypt_message(shared_key, data)
            msg_list.insert(tk.END, decrypted)
        except Exception as e:
            msg_list.insert(tk.END, f"[ERROR] {str(e)}")
            break

def send():
    msg = my_msg.get()
    my_msg.set("")
    if msg:
        full_msg = f"{NAME}: {msg}"
        msg_list.insert(tk.END, full_msg)
        encrypted = crypto.encrypt_message(shared_key, full_msg)
        CLIENT.send(encrypted)

def on_closing(event=None):
    msg_list.insert(tk.END, "going offline...")
    time.sleep(1)
    CLIENT.close()
    top.quit()
    sys.exit()

top.protocol("WM_DELETE_WINDOW", on_closing)
receive_thread = Thread(target=receive)
receive_thread.start()
tk.mainloop()
