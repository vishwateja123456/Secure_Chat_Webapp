import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
import secure_crypto as crypto
import sys

# Settings 
BUFFER_SIZE = 4096
BG_COLOR = "#1e1e2f"
TEXT_COLOR = "#ffffff"
ENTRY_BG = "#2e2e3f"
BUTTON_BG = "#5c5cad"
BUTTON_FG = "#ffffff"
FONT = ("Helvetica", 12)

#  Connect to Server 
def connect_to_server(host, port, name):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))

        # Diffie-Hellman Key Exchange
        private_key, public_key = crypto.generate_dh_key_pair()
        client.send(crypto.serialize_public_key(public_key))
        peer_bytes = client.recv(BUFFER_SIZE)
        peer_public_key = crypto.deserialize_public_key(peer_bytes)
        shared_key = crypto.derive_shared_key(private_key, peer_public_key)

        return client, shared_key
    except Exception as e:
        print(f"Connection Error: {e}")
        sys.exit(1)

# GUI Class 
class ChatClient:
    def __init__(self, root, client_socket, shared_key, name):
        self.root = root
        self.client = client_socket
        self.shared_key = shared_key
        self.name = name

        self.root.title(f"Secure Chat - {name}")
        self.root.geometry("600x600")
        self.root.configure(bg=BG_COLOR)

        self.header = tk.Label(root, text=f"Secure Chat - {name}", bg=BG_COLOR, fg=TEXT_COLOR, font=("Helvetica", 16, "bold"))
        self.header.pack(pady=10)

        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, bg=ENTRY_BG, fg=TEXT_COLOR, font=FONT)
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_area.config(state=tk.DISABLED)

        self.entry_frame = tk.Frame(root, bg=BG_COLOR)
        self.entry_frame.pack(fill=tk.X, padx=10, pady=5)

        self.msg_entry = tk.Entry(self.entry_frame, bg=ENTRY_BG, fg=TEXT_COLOR, font=FONT)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.msg_entry.bind("<Return>", self.send_message)

        self.send_btn = tk.Button(self.entry_frame, text="Send", command=self.send_message, bg=BUTTON_BG, fg=BUTTON_FG, font=FONT, relief=tk.FLAT)
        self.send_btn.pack(side=tk.RIGHT)

        threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message(self, event=None):
        msg = self.msg_entry.get()
        if msg:
            full_msg = f"{self.name}: {msg}"
            encrypted = crypto.encrypt_message(self.shared_key, full_msg)
            self.client.send(encrypted)
            self.display_message(full_msg, align="right")
            self.msg_entry.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                data = self.client.recv(BUFFER_SIZE)
                if not data:
                    break
                decrypted = crypto.decrypt_message(self.shared_key, data)
                self.display_message(decrypted, align="left")
            except Exception as e:
                self.display_message(f"[ERROR] {str(e)}", align="left")
                break

    def display_message(self, message, align="left"):
        self.chat_area.config(state=tk.NORMAL)
        if align == "right":
            self.chat_area.insert(tk.END, f"{message}\n", ("right",))
        else:
            self.chat_area.insert(tk.END, f"{message}\n")
        self.chat_area.tag_configure("right", justify='right')
        self.chat_area.yview(tk.END)
        self.chat_area.config(state=tk.DISABLED)

#  Main Function 
if __name__ == "__main__":
    HOST = input("Enter server IP: ")
    PORT = int(input("Enter server Port: "))
    NAME = input("Enter your name: ")

    client_socket, shared_key = connect_to_server(HOST, PORT, NAME)

    root = tk.Tk()
    app = ChatClient(root, client_socket, shared_key, NAME)
    root.protocol("WM_DELETE_WINDOW", lambda: (client_socket.close(), root.destroy()))
    root.mainloop()
