from socket import *
from threading import Thread
import secure_crypto as crypto

client_sock = []
public_keys = []

HOST = "10.0.0.48"
PORT = 30805
BUFFER_SIZE = 4096
ADDRESS = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDRESS)
SERVER.listen(5)

print(f"[SERVER STARTED] Listening on {HOST}:{PORT}")
print("[WAITING] Waiting for 2 clients to connect...")

# Accept clients until 2 are ready
while len(client_sock) < 2:
    client, addr = SERVER.accept()
    print(f"[CONNECTED] Client {len(client_sock)+1} from {addr}")
    client_sock.append(client)
    pub_key = client.recv(BUFFER_SIZE)
    public_keys.append(pub_key)
    print(f"[KEY RECEIVED] from Client {len(client_sock)}")

# Exchange public keys
client_sock[0].send(public_keys[1])
client_sock[1].send(public_keys[0])
print("[KEY EXCHANGE COMPLETE]")

# Start forwarding messages
def forward_messages(sender_idx):
    receiver_idx = 1 - sender_idx
    while True:
        try:
            msg = client_sock[sender_idx].recv(BUFFER_SIZE)
            if not msg:
                print(f"[DISCONNECT] Client {sender_idx + 1} disconnected.")
                break
            print(f"[FORWARD] Client {sender_idx + 1} → Client {receiver_idx + 1}")
            client_sock[receiver_idx].send(msg)
        except Exception as e:
            print(f"[ERROR] Forwarding failed: {e}")
            break

Thread(target=forward_messages, args=(0,), daemon=True).start()
Thread(target=forward_messages, args=(1,), daemon=True).start()
print("[MESSAGE RELAY STARTED]")
