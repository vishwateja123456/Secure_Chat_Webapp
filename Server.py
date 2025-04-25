from socket import *
from threading import Thread
import secure_crypto as crypto

client_sock = []
public_keys = []
shared_keys = {}
BUFFER_SIZE = 4096

HOST = "10.0.0.48"  
PORT = 30805
ADDRESS = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDRESS)
SERVER.listen(10)  # can accept up to 10 clients at once

print(f"[SERVER STARTED] Listening on {HOST}:{PORT}")

def handle_client(client):
    # Perform key exchange
    try:
        pub_key = client.recv(BUFFER_SIZE)
        peer_public_key = crypto.deserialize_public_key(pub_key)
        private_key, public_key = crypto.generate_dh_key_pair()
        client.send(crypto.serialize_public_key(public_key))
        shared_key = crypto.derive_shared_key(private_key, peer_public_key)
        shared_keys[client] = shared_key

        while True:
            msg = client.recv(BUFFER_SIZE)
            if not msg:
                print("[DISCONNECT] Client disconnected.")
                client_sock.remove(client)
                del shared_keys[client]
                client.close()
                break
            print("[MESSAGE RECEIVED] Broadcasting...")
            broadcast(msg, sender=client)
    except Exception as e:
        print(f"[ERROR] Client handling failed: {e}")
        if client in client_sock:
            client_sock.remove(client)
        if client in shared_keys:
            del shared_keys[client]
        client.close()

def broadcast(message, sender=None):
    for client in client_sock:
        if client != sender:
            try:
                client.send(message)
            except Exception as e:
                print(f"[ERROR] Failed to send to a client: {e}")

# Accept incoming connections
while True:
    client, addr = SERVER.accept()
    print(f"[CONNECTED] {addr}")
    client_sock.append(client)
    Thread(target=handle_client, args=(client,), daemon=True).start()
