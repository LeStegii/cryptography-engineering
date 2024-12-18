import socket
import ssl
import threading
import traceback
from typing import Optional

from ecdsa import VerifyingKey

from homework2.lecture4 import x3dh_utils


class Server:
    def __init__(self, host: str = "localhost", port: int = 25566):
        self.host: str = host
        self.port: int = port
        self.server_socket: Optional[ssl.SSLSocket] = None
        self.connections: dict[tuple[str, int], ssl.SSLSocket] = {}  # List of connected clients (addr, socket)
        self.registered_clients: dict[str, tuple[str, int]] = {}  # List of registered clients (username, addr)
        self.key_bundles: dict[str, dict[str, VerifyingKey | bytes]] = {}  # List of key bundles (username, keys)

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
                self.connections[self.registered_clients[recipient]].send(message)
                return b"SUCCESS"
            except Exception:
                traceback.print_exc()
                print(f"Failed to send message to {recipient}.")
                return b"FAILED"

    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple[str, int]):
        try:
            while True:
                message = client_socket.recv(4096)
                if message:
                    message = x3dh_utils.decode_message(message)
                    if message["type"] == "REGISTER":

                        username = message["username"]
                        if username in self.registered_clients:
                            client_socket.send(x3dh_utils.encode_message({"type": "ALREADY_REGISTERED"}))
                            client_socket.close()
                            print(f"Client {addr} tried to register as {username} but it is already registered.")
                            break
                        self.registered_clients[username] = (addr[0], int(addr[1]))

                        self.key_bundles[username] = {
                            "IPK": message["IPK"],
                            "SPK": message["SPK"],
                            "sigma": message["sigma"],
                            "OPK": message["OPK"]
                        }

                        client_socket.send(x3dh_utils.encode_message({"type": "REGISTERED"}))
                        print(f"Client {addr} registered as {username}.")
                        continue

                    if message["type"] == "X3DH_REQUEST":
                        username = message["target"]
                        if username not in self.registered_clients or username not in self.key_bundles:
                            client_socket.send(x3dh_utils.encode_message({"type": "X3DH_KEY", "status": "FAILED"}))
                            print(f"Client {addr} tried to request keys for {username} but this user isn't registered.")
                            continue

                        client_socket.send(x3dh_utils.encode_message({
                            "type": "X3DH_KEY",
                            "owner": username,
                            "status": "SUCCESS",
                            "key_bundle": self.key_bundles[username]
                        }))
                        print(f"Client {addr} requested keys for {username}.")
                        continue

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
