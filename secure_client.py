import socket
import threading
import json
import sys
import time
import argparse
from crypto_core import RSAEngine, PublicKey, PrivateKey

class SecureClient:
    """Manages the user's keys, network connection, and chat interface."""
    
    def __init__(self, username: str, host: str, port: int, secure_mode: bool, key_size: int = 32):
        self.username = username
        self.host = host
        self.port = port
        self.secure_mode = secure_mode
        
        # 1. State Management
        print(f"[{self.username}] Generating RSA keys ({key_size} bits)...")
        self.public_key, self.private_key = RSAEngine.generate_keypair(key_size)
        self.ca_public_key: PublicKey | None = None
        self.peer_keys: dict[str, PublicKey] = {}
        
        # 2. Network Setup
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        """Establishes connection and starts the background listener."""
        try:
            self.sock.connect((self.host, self.port))
            print(f"[{self.username}] Connected to Server at {self.host}:{self.port}")
        except Exception as e:
            print(f"[{self.username}] Failed to connect: {e}")
            sys.exit(1)

        # Start listening for messages in the background
        listener = threading.Thread(target=self._listen_loop, daemon=True)
        listener.start()

        # Send Handshake
        self._send_hello()

    # --- Outgoing Network Actions ---

    def _send_hello(self):
        """Registers with the server."""
        packet = {
            "type": "HELLO",
            "client_id": self.username,
            "public_key": [self.public_key.e, self.public_key.n]
        }
        self.sock.sendall(json.dumps(packet).encode('utf-8'))

    def _request_key(self, target_user: str):
        """Asks the server for another user's public key."""
        packet = {
            "type": "REQ_KEY",
            "target_id": target_user
        }
        self.sock.sendall(json.dumps(packet).encode('utf-8'))

    def send_chat_message(self, target_user: str, text: str):
        """Encrypts and sends a message to another user."""
        # Check if we have the key. If not, request it and wait.
        if target_user not in self.peer_keys:
            print(f"[{self.username}] Requesting public key for {target_user}...")
            self._request_key(target_user)
            
            # Simple polling wait (up to 3 seconds) for the background thread to save the key
            for _ in range(30):
                if target_user in self.peer_keys:
                    break
                time.sleep(0.1)
                
            if target_user not in self.peer_keys:
                print(f"[{self.username}] ERROR: Could not retrieve key for {target_user}.")
                return

        # We have the key! Let's encrypt.
        target_pub_key = self.peer_keys[target_user]
        ciphertext = RSAEngine.encrypt_string(text, target_pub_key)
        
        packet = {
            "type": "MSG",
            "from": self.username,
            "to": target_user,
            "payload": ciphertext
        }
        self.sock.sendall(json.dumps(packet).encode('utf-8'))
        print(f"[{self.username}] Message sent to {target_user} (Encrypted).")

    # --- Incoming Network Actions (Background Thread) ---

    def _listen_loop(self):
        """Continuously listens for incoming server packets."""
        try:
            while True:
                data = self.sock.recv(4096)
                if not data: break
                
                packet = json.loads(data.decode('utf-8'))
                msg_type = packet.get("type")

                if msg_type == "HELLO_ACK":
                    self._handle_hello_ack(packet)
                elif msg_type == "RESP_KEY":
                    self._handle_key_response(packet)
                elif msg_type == "MSG":
                    self._handle_incoming_chat(packet)
                elif msg_type == "ERROR":
                    print(f"\n[SERVER ERROR] {packet.get('message')}")

        except ConnectionResetError:
            print("\n[SYSTEM] Connection to server lost.")
            sys.exit(1)

    def _handle_hello_ack(self, packet: dict):
        ca_data = packet.get("ca_public_key")
        if ca_data:
            self.ca_public_key = PublicKey(ca_data[0], ca_data[1])
            print(f"[{self.username}] CA Trust Anchor Acquired.")

    def _handle_key_response(self, packet: dict):
        target = packet["target_id"]
        pub_data = packet["public_key"]
        signature = packet.get("signature")
        
        target_pub = PublicKey(pub_data[0], pub_data[1])

        # VERIFICATION LOGIC (The core of the project)
        if self.secure_mode:
            if not signature or not self.ca_public_key:
                print(f"\n[SECURITY ALERT] Missing signature or CA Key for {target}!")
                return
            
            payload = f"{target}:{target_pub.e}:{target_pub.n}"
            is_valid = RSAEngine.verify_signature(payload, signature, self.ca_public_key)
            
            if is_valid:
                print(f"[{self.username}] Signature verified. Saved {target}'s key.")
                self.peer_keys[target] = target_pub
            else:
                print(f"\n[FATAL SECURITY ALERT] MITM DETECTED! Signature verification failed for {target}!")
        else:
            # Unprotected mode: Just blindly trust the key
            print(f"[{self.username}] Saved {target}'s key (UNPROTECTED).")
            self.peer_keys[target] = target_pub

    def _handle_incoming_chat(self, packet: dict):
        sender = packet["from"]
        ciphertext = packet["payload"]
        try:
            plaintext = RSAEngine.decrypt_string(ciphertext, self.private_key)
            print(f"\n--- New Message from {sender} ---")
            print(f"Ciphertext: {ciphertext[:20]}...")
            print(f"Plaintext : {plaintext}")
            print("---------------------------------")
        except Exception as e:
            print(f"\n[{self.username}] Failed to decrypt message from {sender}: {e}")

    # --- UI Loop ---
    def start_console(self):
        """Runs the interactive command prompt for the user."""
        print(f"\n=== Chat Console ({'SECURE' if self.secure_mode else 'UNPROTECTED'}) ===")
        print("Type: msg <user> <message>  |  exit to quit\n")
        
        while True:
            try:
                user_input = input(f"[{self.username}] > ").strip()
                if not user_input: continue
                
                parts = user_input.split(" ", 2)
                cmd = parts[0].lower()

                if cmd == "msg" and len(parts) == 3:
                    target = parts[1]
                    text = parts[2]
                    self.send_chat_message(target, text)
                elif cmd == "exit":
                    break
                else:
                    print("Invalid command. Use: msg <user> <message>")
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="Your username (e.g., Alice)")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--secure", action="store_true", help="Enable CA signature verification")
    parser.add_argument("--keysize", type=int, default=32)
    args = parser.parse_args()

    client = SecureClient(args.name, "127.0.0.1", args.port, args.secure, args.keysize)
    client.connect()
    client.start_console()