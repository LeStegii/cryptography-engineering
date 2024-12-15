import socket
import ssl
import threading
import traceback
from typing import Optional


class Server:
    def __init__(self, host: str = "localhost", port: int = 25566):
        self.host: str = host
        self.port: int = port
        self.server_socket: Optional[ssl.SSLSocket] = None
        self.connections: dict[tuple[str, int], ssl.SSLSocket] = {}  # List of connected clients (addr, socket)
        self.registered_clients: dict[str, tuple[str, int]] = {}  # List of registered clients (username, addr)

    def start(self):
        try:
            # Set up raw socket
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.bind((self.host, self.port))
            raw_socket.listen(5)

            # Wrap with SSL
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
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
                if recipient not in self.registered_clients:
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
                message = client_socket.recv(1024)
                if message:
                    print(f"Message from {addr}: {message.decode()}")
                else:
                    print(f"Client {addr} disconnected.")
                    break
        except Exception as e:
            traceback.print_exc()
            print(f"Error with client {addr}.")
        finally:
            client_socket.close()
            self.connections.pop(addr)
            print(f"Connection with {addr} closed.")


if __name__ == "__main__":
    import sys

    HOST = "localhost" if len(sys.argv) < 3 else sys.argv[2]
    PORT = 25566 if len(sys.argv) < 4 else int(sys.argv[3])

    server = Server(HOST, PORT)
    server.start()
