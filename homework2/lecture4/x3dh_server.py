import socket
import ssl
import threading
import traceback
from typing import Optional

from ecdsa import VerifyingKey


class Server:
    def __init__(self, host: str = "localhost", port: int = 25566):
        self.host: str = host
        self.port: int = port
        self.server_socket: Optional[ssl.SSLSocket] = None
        self.connections: dict[tuple[str, int], ssl.SSLSocket] = {}  # List of connected clients (addr, socket)
        self.registered_clients: dict[bytes, tuple[str, int]] = {}  # List of registered clients (username, addr)
        self.key_bundles: dict[bytes, dict[str, VerifyingKey | bytes]] = {}  # List of key bundles (username, keys)

    def start(self):
        try:
            # Set up raw socket
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.bind((self.host, self.port))
            raw_socket.listen(5)

            # Wrap with SSL
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile="server.pem", keyfile="server.key")
            self.server_socket = context.wrap_socket(raw_socket, server_side=True)

            print(f"Server started on {self.host}:{self.port}")

            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"New connection from {addr}")
                self.connections[addr] = client_socket

                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                client_thread.start()
        except Exception:
            traceback.print_exc()
            print("Error starting the server.")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def broadcast(self, message: bytes, sender_socket: ssl.SSLSocket):
        for client in self.connections.values():
            if client != sender_socket:
                try:
                    client.send(message)
                except Exception:
                    traceback.print_exc()
                    print("Failed to send message to a client.")

    def send(self, message: bytes, recipient: tuple[str, int] | str) -> bytes:
        if isinstance(recipient, tuple):
            try:
                if recipient not in self.connections:
                    return b"NOT_CONNECTED"
                self.connections[recipient].send(message)
                return b"SUCCESS"
            except Exception:
                traceback.print_exc()
                print(f"Failed to send message to {recipient}.")
                return b"FAILED"
        elif isinstance(recipient, str):
            try:
                if recipient.encode() not in self.registered_clients:
                    return b"NOT_REGISTERED"
                self.connections[self.registered_clients[recipient.encode()]].send(message)
                return b"SUCCESS"
            except Exception:
                traceback.print_exc()
                print(f"Failed to send message to {recipient}.")
                return b"FAILED"

    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple[str, int]):
        try:
            while True:
                message = client_socket.recv(1024)
                if message:
                    if message.startswith(b"REGISTER"):
                        username_hex_bytes, ipk_hex_bytes, spk_hex_bytes, sigma_hex_bytes, opk_hex_bytes = message.split(b"   ")[1:]
                        username = bytes.fromhex(username_hex_bytes.decode())
                        if username in self.registered_clients:
                            client_socket.send(b"ALREADY_REGISTERED")
                            client_socket.close()
                            print(f"Client {addr} tried to register as {username.decode()} but it is already registered.")
                            break
                        self.registered_clients[username] = (addr[0], int(addr[1]))

                        self.key_bundles[username] = {
                            "IPK": VerifyingKey.from_pem(bytes.fromhex(ipk_hex_bytes.decode()).decode()),
                            "SPK": VerifyingKey.from_pem(bytes.fromhex(spk_hex_bytes.decode()).decode()),
                            "sigma": bytes.fromhex(sigma_hex_bytes.decode()),
                            "OPK": VerifyingKey.from_pem(bytes.fromhex(spk_hex_bytes.decode()).decode())
                        }

                        client_socket.send(b"REGISTERED")

                else:
                    print(f"Client {addr} disconnected.")
                    break
        except Exception as e:
            traceback.print_exc()
            print(f"Error with client {addr}.")
        finally:
            client_socket.close()
            self.connections.pop(addr)

            # If client was registered, remove from registered clients
            for username, client_addr in self.registered_clients.items():
                if client_addr == addr:
                    self.registered_clients.pop(username)
                    self.key_bundles.pop(username)
                    break

            print(f"Connection with {addr} closed.")


if __name__ == "__main__":
    import sys

    HOST = "localhost" if len(sys.argv) < 3 else sys.argv[2]
    PORT = 25566 if len(sys.argv) < 4 else int(sys.argv[3])

    server = Server(HOST, PORT)
    server.start()
