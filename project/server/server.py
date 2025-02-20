import os
import socket
import ssl
import threading
import traceback
from ssl import SSLSocket
from typing import Optional

import utils
from project.client.client import enable_debug
from project.database import Database
from project.message import MESSAGE, Message, STATUS, REGISTER, REQUEST_SALT, ANSWER_SALT, IDENTITY, LOGIN, ERROR, \
    SUCCESS


class Server:
    def __init__(self, host: str = "localhost", port: int = 25567):
        self.host: str = host
        self.port: int = port
        self.server_socket: Optional[ssl.SSLSocket] = None
        self.sockets: dict[tuple[str, int], ssl.SSLSocket] = {}  # List of connected clients (addr, socket)
        self.connections: dict[str, tuple[str, int]] = {}  # List of connected clients (username, addr)

        self.database = Database("database.csv", "server-key.txt")

    def username(self, addr: tuple[str, int]) -> Optional[str]:
        for username, client_addr in self.connections.items():
            if client_addr == addr:
                return username
        return None

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

                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                client_thread.start()
        except Exception:
            traceback.print_exc()
            print("Error starting the server.")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def broadcast(self, message: bytes, sender_socket: ssl.SSLSocket):
        for client in self.sockets.values():
            if client != sender_socket:
                try:
                    client.send(message)
                except Exception:
                    traceback.print_exc()
                    print("Failed to send message to a client.")

    def send_bytes(self, message: bytes, recipient: tuple[str, int] | str | SSLSocket) -> bool:

        target = None
        if isinstance(recipient, tuple):
            if recipient in self.sockets:
                target = self.sockets[recipient]
        elif isinstance(recipient, str):
            if recipient in self.connections and self.connections[recipient] in self.sockets:
                target = self.sockets[self.connections[recipient]]
        elif isinstance(recipient, SSLSocket):
            target = recipient

        if target is None:
            print(f"Client {recipient} not found.")
            return False

        try:
            target.send(message)
            return True
        except Exception:
            traceback.print_exc()
            print("Failed to send the message.")
            return False

    def send(self, receiver: str, content: dict[str, any], type: str = MESSAGE, socket: Optional[ssl.SSLSocket] = None):
        try:
            message = Message(message=utils.encode_message(content), sender="server", receiver=receiver, type=type)
            self.send_bytes(message.to_bytes(), receiver if not socket else socket)
        except Exception:
            traceback.print_exc()
            print("Failed to send the message.")

    def is_registered(self, username: str) -> bool:
        return self.database.has(username) and self.database.get(username).get("registered") == True

    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple[str, int]):
        try:

            print("Handling client.")

            # Initial message has to be the identity of the client
            received_bytes = client_socket.recv(1024)

            print("Received bytes.")

            if not received_bytes:
                print(f"Received empty message from {addr}. Closing connection.")
                return

            message = Message.from_bytes(received_bytes)
            if message.type != IDENTITY:
                self.send("unknown", {"status": ERROR, "error": "You must send an identity message first."}, STATUS, client_socket)
                raise Exception("Client did not send an identity message first.")

            if not message.sender or not message.dict().get("username"):
                self.send("unknown", {"status": ERROR, "error": "You must send a valid identity message."}, STATUS, client_socket)
                raise Exception("Client did not send a valid identity message.")

            username = message.dict().get("username")

            if self.connections.get(username):
                self.send("unknown", {"status": ERROR, "error": "A user with this name is already connected."}, STATUS, client_socket)
                raise Exception(f"Client {addr} tried to connect as {username}, but a user with this name is already connected.")


            self.connections[message.sender] = addr
            self.sockets[addr] = client_socket

            if not self.database.has(message.sender):
                print(f"{addr} connected as {message.sender}. User is currently not registered.")
                self.send(message.sender, {"status": "NOT_REGISTERED"}, STATUS)
            else:
                print(f"{addr} sent STATUS_REQUEST as {message.sender}. Answering with REGISTERED.")
                self.send(message.sender, {"status": "REGISTERED"}, STATUS)



            while True:
                received_bytes = client_socket.recv(4096)
                if not received_bytes:
                    print(f"Received empty message from {addr}. Closing connection.")
                    break
                message = Message.from_bytes(received_bytes)

                if message:

                    type = message.type
                    receiver = message.receiver
                    sender = message.sender
                    content = message.dict()

                    if receiver != "server" and type != MESSAGE:
                        print(f"Client {addr} (as {sender}) tried to send a non-message type message to {receiver}.")
                        continue

                    # print(f"\nReceived message from {addr} as {sender} with type {type}:\n{content}\n")

                    ####################################################################################################

                    if type == REQUEST_SALT:
                        print(f"{addr} sent REQUEST_SALT as {sender}. Sending salt.")
                        self.send(sender, {"salt": self.get_or_gen_salt(sender)}, ANSWER_SALT)

                    ####################################################################################################

                    elif type == REGISTER:

                        if self.is_registered(sender):
                            print(f"{addr} sent REGISTER as {sender}, but the user is already registered.")
                            self.send(sender, {"status": ERROR, "error": "User is already registered."}, REGISTER)
                            continue

                        user_known = self.database.has(sender)
                        salt_set = user_known and self.database.get(sender).get("salt")

                        print(f"{addr} sent REGISTER as {sender}.")

                        salt = self.get_or_gen_salt(sender)
                        if not salt_set:
                            print("Creating salt.")
                            self.database.update(sender, {"salt": salt})

                        print(f"Saving password.")
                        password = content.get("password")
                        salted_password = utils.salt_password(password, self.database.get(sender).get("salt"))
                        self.database.update(sender, {"salted_password": salted_password, "registered": True})
                        self.send(sender, {"status": SUCCESS, "salt": salt}, REGISTER)

                    ####################################################################################################

                    if type == LOGIN:
                        if not self.is_registered(sender):
                            print(f"{addr} sent LOGIN as {sender}, but the user is not registered.")
                            self.send(sender, {"status": "NOT_REGISTERED"}, LOGIN)
                        else:
                            print(f"{addr} sent LOGIN as {sender}. User is registered. Checking password.")
                            salted_password = content.get("salted_password")
                            if salted_password == self.database.get(sender).get("salted_password"):
                                print(f"Password correct.")
                                self.send(sender, {"status": SUCCESS}, LOGIN)
                                self.database.update(sender, {"logged_in": True})
                            else:
                                print(f"Password incorrect.")
                                self.send(sender, {"status": ERROR, "error": "Password incorrect."}, LOGIN)

                    ####################################################################################################




                    continue
                else:
                    print(f"Client {addr} disconnected.")
                    break
        except Exception as e:
            if enable_debug:
                traceback.print_exc()
            print(f"Error with client {addr}: {e}")
        finally:
            client_socket.close()
            self.connections.pop(self.username(addr), None)
            self.sockets.pop(addr, None)
            print(f"Connection with {addr} closed.")

    def get_or_gen_salt(self, sender: str) -> bytes:
        has_salt = self.database.has(sender) and "salt" in self.database.get(sender)

        if not has_salt:
            salt = os.urandom(32)
            self.database.insert(sender, {"salt": salt})
        else:
            salt = self.database.get(sender).get("salt")
        return salt


if __name__ == "__main__":
    server = Server()
    server.start()
