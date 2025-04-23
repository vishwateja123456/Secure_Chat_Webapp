# streamlit_client_1.py
import streamlit as st
import socket
import threading
import secure_crypto as crypto
import queue

# Global queue for thread-safe communication
message_queue = queue.Queue()

# UI setup
st.set_page_config(page_title="Entice Chat - Client 1", layout="centered")
st.title("🔌 Entice Chat - Client 1 (Web)")

# Session state defaults
if 'connected' not in st.session_state:
    st.session_state.connected = False
    st.session_state.messages = []
    st.session_state.client = None
    st.session_state.shared_key = None
    st.session_state.name = ""
if 'relay_ready' not in st.session_state:
    st.session_state.relay_ready = False

# Inputs
host = st.text_input("Server Host", value="10.0.0.155")
port = st.number_input("Server Port", value=42000)
name = st.text_input("Your Name", value="Client1")

# Connect button
if st.button("Connect") and not st.session_state.connected:
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((host, port))

        # DH Key Exchange
        private_key, public_key = crypto.generate_dh_key_pair()
        client.send(crypto.serialize_public_key(public_key))
        peer_bytes = client.recv(4096)
        peer_public_key = crypto.deserialize_public_key(peer_bytes)
        shared_key = crypto.derive_shared_key(private_key, peer_public_key)

        # Update session state
        st.session_state.client = client
        st.session_state.shared_key = shared_key
        st.session_state.connected = True
        st.session_state.name = name
        st.session_state.messages = []
        st.session_state.relay_ready = True

        st.success(f"Connected to {host}:{port} as {name}")

        # Thread to receive messages
        def receive():
            message_queue.put(f"🟢 Connected to {host}:{port} as {name}")
            while True:
                try:
                    data = client.recv(4096)
                    if not data:
                        break
                    msg = crypto.decrypt_message(shared_key, data)
                    message_queue.put(msg)
                except Exception as e:
                    message_queue.put(f"[ERROR] {str(e)}")
                    break

        threading.Thread(target=receive, daemon=True).start()

    except Exception as e:
        st.error(f"Connection failed: {e}")

# Chat section
if st.session_state.connected:
    # Sync thread messages to Streamlit safely
    while not message_queue.empty():
        st.session_state.messages.append(message_queue.get())

    for msg in st.session_state.messages:
        st.markdown(f"`{msg}`")

    if st.session_state.relay_ready:
        user_input = st.text_input("Type a message", key="input")
        if st.button("Send"):
            if user_input and st.session_state.client:
                try:
                    full_msg = f"{st.session_state.name}: {user_input}"
                    st.session_state.messages.append(full_msg)
                    encrypted = crypto.encrypt_message(st.session_state.shared_key, full_msg)
                    st.session_state.client.send(encrypted)
                except Exception as e:
                    st.error(f"Failed to send message: {e}")
    else:
        st.warning("Waiting for the other client to connect...")
