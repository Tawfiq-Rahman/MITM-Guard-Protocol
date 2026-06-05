import socket
import threading
import json
import logging
import argparse
from dataclasses import dataclass
from crypto_core import RSAEngine, PublicKey, PrivateKey

# --- Configure Logging for a Professional Console Output ---
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

@dataclass
class ConnectedClient:
    """Stores information about an active user."""
    connection: socket.socket
    address: tuple
    public_key: PublicKey

# --- Component 1: The Certificate Authority ---
class CertificateAuthority:
    """Manages the Master Trust Anchor keys and signing."""
    def __init__(self, key_size: int = 32):
        logging.info(f"CA: Generating Master Keys ({key_size} bits)...")
        self.public_key, self.private_key = RSAEngine.generate_keypair(key_size)
        logging.info(f"CA: Master Public Key initialized: (e={self.public_key.e}, n={self.public_key.n})")

    def sign_client_key(self, client_id: str, client_pub: PublicKey) -> int:
        """Creates a digital signature for a client's public key."""
        # The payload structure must match exactly what the client will verify
        payload = f"{client_id}:{client_pub.e}:{client_pub.n}"
        signature = RSAEngine.sign_data(payload, self.private_key)
        return signature

# --- Component 2: The Network Server ---
class SecureRelayServer:
    """Handles TCP connections, routing, and integrates the CA."""
    def __init__(self, host: str, port: int, secure_mode: bool = False, key_size: int = 32):
        self.host = host
        self.port = port
        self.secure_mode = secure_mode
        self.active_clients: dict[str, ConnectedClient] = {}
        
        # Initialize CA only if secure mode is enabled
        self.ca = CertificateAuthority(key_size) if secure_mode else None

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        """Starts listening for incoming client connections."""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        mode_text = "SECURE (CA Enabled)" if self.secure_mode else "UNPROTECTED"
        logging.info(f"SERVER: Listening on {self.host}:{self.port} [{mode_text}]")

        try:
            while True:
                conn, addr = self.server_socket.accept()
                # Spin up a new thread for every client that connects
                client_thread = threading.Thread(target=self._handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logging.info("SERVER: Shutting down...")
            self.server_socket.close()

    def _handle_client(self, conn: socket.socket, addr: tuple):
        """The main loop for interacting with a connected client."""
        logging.info(f"NETWORK: New connection from {addr}")
        client_id = None

        try:
            while True:
                data = conn.recv(4096)
                if not data: break

                try:
                    packet = json.loads(data.decode('utf-8'))
                except json.JSONDecodeError:
                    continue

                msg_type = packet.get("type")

                # Handle Registration
                if msg_type == "HELLO":
                    client_id = packet["client_id"]
                    pub_key = PublicKey(packet["public_key"][0], packet["public_key"][1])
                    self.active_clients[client_id] = ConnectedClient(conn, addr, pub_key)
                    
                    logging.info(f"SERVER: Registered user '{client_id}'")
                    
                    # Respond with CA Key if secure
                    response = {"type": "HELLO_ACK", "status": "OK", "ca_public_key": None}
                    if self.secure_mode and self.ca:
                        response["ca_public_key"] = [self.ca.public_key.e, self.ca.public_key.n]
                    
                    conn.sendall(json.dumps(response).encode('utf-8'))

                # Handle Key Discovery requests
                elif msg_type == "REQ_KEY":
                    target_id = packet["target_id"]
                    
                    if target_id in self.active_clients:
                        target_pub = self.active_clients[target_id].public_key
                        response = {
                            "type": "RESP_KEY",
                            "target_id": target_id,
                            "public_key": [target_pub.e, target_pub.n],
                            "signature": None
                        }

                        # Apply CA Signature if secure mode is on
                        if self.secure_mode and self.ca:
                            sig = self.ca.sign_client_key(target_id, target_pub)
                            response["signature"] = sig
                            logging.info(f"CA: Signed key for '{target_id}'")

                        conn.sendall(json.dumps(response).encode('utf-8'))
                    else:
                        error_msg = {"type": "ERROR", "message": "User not found"}
                        conn.sendall(json.dumps(error_msg).encode('utf-8'))

                # Handle Message Routing
                elif msg_type == "MSG":
                    to_user = packet["to"]
                    if to_user in self.active_clients:
                        target_conn = self.active_clients[to_user].connection
                        # Route the exact packet forward
                        target_conn.sendall(data)
                        logging.info(f"ROUTER: Relayed message {packet['from']} -> {to_user}")

        except ConnectionResetError:
            pass
        finally:
            if client_id and client_id in self.active_clients:
                del self.active_clients[client_id]
            conn.close()
            logging.info(f"NETWORK: Connection closed for {addr}")

# --- Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Chat Relay Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    parser.add_argument("--secure", action="store_true", help="Enable Certificate Authority mode")
    parser.add_argument("--keysize", type=int, default=32, help="RSA Key size in bits")
    args = parser.parse_args()

    server = SecureRelayServer(host="0.0.0.0", port=args.port, secure_mode=args.secure, key_size=args.keysize)
    server.start()