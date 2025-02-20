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
from project.project_utils import is_valid_message, debug, check_username


class Server:
    def __init__(self, host: str = "localhost", port: int = 25567):
        self.host: str = host
        self.port: int = port
        self.server_socket: Optional[ssl.SSLSocket] = None
        self.sockets: dict[tuple[str, int], ssl.SSLSocket] = {}  # List of connected clients (addr, socket)
        self.connections: dict[str, tuple[str, int]] = {}  # List of connected clients (username, addr)

        self.database = Database("database.csv", "server-key.txt")

        self.handlers: dict[str, any] = {
            REGISTER: self.handle_register,
            LOGIN: self.handle_login,
            REQUEST_SALT: self.handle_request_salt
        }

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

            debug(f"Server started on {self.host}:{self.port}")

            while True:
                client_socket, addr = self.server_socket.accept()
                debug(f"New connection from {addr}")

                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True)
                client_thread.start()
        except Exception:
            traceback.print_exc()
            debug("Error starting the server.")
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
                    debug("Failed to send message to a client.")

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
            debug(f"Client {recipient} not found.")
            return False

        try:
            target.send(message)
            return True
        except Exception:
            traceback.print_exc()
            debug("Failed to send the message.")
            return False

    def send(self, receiver: str | Optional[ssl.SSLSocket], content: dict[str, any], type: str = MESSAGE):
        try:
            message = Message(
                message=utils.encode_message(content),
                sender="server",
                receiver=receiver if isinstance(receiver, str) else "unknown",
                type=type
            )
            self.send_bytes(message.to_bytes(), receiver)
        except Exception:
            traceback.print_exc()
            debug(f"Failed to send the message to {receiver}.")

    def is_registered(self, username: str) -> bool:
        return self.database.has(username) and self.database.get(username).get("registered") == True

    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple[str, int]):
        try:

            debug(f"Handling client {addr}. Checking it's identity.")
            if not self.check_identity(client_socket, addr):
                return

            while True:
                received_bytes = client_socket.recv(4096)
                if not received_bytes:
                    debug(f"Received empty message from {addr}. Closing connection.")
                    break
                message = Message.from_bytes(received_bytes)

                if is_valid_message(message):

                    type = message.type
                    if message.type:

                        if message.receiver != "server" and type != MESSAGE:
                            debug(
                                f"{message.sender} ({addr}) tried to send a non-message type message to {message.receiver}.")
                            continue

                        handler = self.handlers.get(type, self.handle_unknown)
                        handler(message, client_socket, addr)
                    continue
                else:
                    debug(f"Client {addr} sent an invalid message. Closing connection.")
                    break
        except Exception as e:
            if enable_debug:
                traceback.print_exc()
            debug(f"Error with client {addr}: {e}")
        finally:
            client_socket.close()
            self.connections.pop(self.username(addr), None)
            self.sockets.pop(addr, None)
            debug(f"Connection with {addr} closed.")

    def handle_login(self, message: Message, client: SSLSocket, addr: tuple[str, int]):
        content = message.dict()
        if not self.is_registered(message.sender):
            debug(f"{message.sender}'s ({addr}) tried to login but isn't registered.")
            self.send(message.sender, {"status": "NOT_REGISTERED"}, LOGIN)
        else:
            debug(f"{message.sender} ({addr}) sent login request, checking password...")
            salted_password = content.get("salted_password")
            if salted_password == self.database.get(message.sender).get("salted_password"):
                debug(f"{message.sender}'s ({addr}) password is correct. User is now logged in.")
                self.send(message.sender, {"status": SUCCESS}, LOGIN)
                self.database.update(message.sender, {"logged_in": True})
            else:
                debug(f"{message.sender}'s ({addr}) password is incorrect!")
                self.send(message.sender, {"status": ERROR, "error": "Password incorrect."}, LOGIN)

    def handle_register(self, message: Message, client: SSLSocket, addr: tuple[str, int]):
        content = message.dict()
        if self.is_registered(message.sender):
            debug(f"{message.sender} ({addr}) tried to register, but the user is already registered.")
            self.send(message.sender, {"status": ERROR, "error": "User is already registered."}, REGISTER)
            return

        user_known = self.database.has(message.sender)
        salt_set = user_known and self.database.get(message.sender).get("salt")

        debug(f"{message.sender} ({addr}) is trying to register.")

        salt = self.get_or_gen_salt(message.sender)
        if not salt_set:
            debug(f"Creating salt for {message.sender} ({addr}).")
            self.database.update(message.sender, {"salt": salt})

        debug(f"Saving password for {message.sender} ({addr}). Sending salt to client.")
        password = content.get("password")
        salted_password = utils.salt_password(password, self.database.get(message.sender).get("salt"))
        self.database.update(message.sender, {"salted_password": salted_password, "registered": True})
        self.send(message.sender, {"status": SUCCESS, "salt": salt}, REGISTER)

    def handle_request_salt(self, message: Message, client: SSLSocket, addr: tuple[str, int]):
        debug(f"{addr} sent REQUEST_SALT as {message.sender}. Sending salt.")
        self.send(message.sender, {"salt": self.get_or_gen_salt(message.sender)}, ANSWER_SALT)

    def handle_unknown(self, message: Message, client: SSLSocket, addr: tuple[str, int]):
        debug(
            f"{message.sender} ({addr}) sent message of unknown type '{message.type}'. Closing connection to be safe.")
        client.close()

    def get_or_gen_salt(self, sender: str) -> bytes:
        """
        Returns the salt of the user with the given name.
        If no salt exists in the database, a salt will be generated and saved.
        :param sender: The name of the user
        :return: The user's salt
        """
        has_salt = self.database.has(sender) and "salt" in self.database.get(sender)

        if not has_salt:
            salt = os.urandom(32)
            self.database.insert(sender, {"salt": salt})
        else:
            salt = self.database.get(sender).get("salt")
        return salt

    def check_identity(self, client_socket: SSLSocket, addr: tuple[str, int]) -> bool:
        """
        Checks the initial message sent by the client.
        The initial message has to be of type 'identity' and contain a username.
        :param client_socket The user's socket
        :param addr: The user's address
        :return Whether the check was successful
        """
        received_bytes = client_socket.recv(1024)
        debug("Received bytes.")

        if not received_bytes:
            debug(f"{addr}'s first message was empty.")
            return False

        message = Message.from_bytes(received_bytes)

        if not is_valid_message(message):
            debug(f"{addr}'s first message couldn't be decoded.")
            return False

        if message.type != IDENTITY:
            self.send(client_socket, {"status": ERROR, "error": "You must send an identity message first."}, STATUS)
            debug(f"{addr} didn't send an identy message as their first message.")
            return False

        username = message.dict().get("username")

        if not message.sender or not message.sender == username or not check_username(username):
            self.send(client_socket, {"status": ERROR, "error": "You must send a valid identity message."}, STATUS)
            debug(f"{addr} did not send a valid identity message (error with username).")
            return False

        if self.connections.get(username):
            self.send(client_socket, {"status": ERROR, "error": "A user with this name is already connected."},
                      STATUS, )
            debug(f"{addr} tried to connect as {username}, but a user with this name is already connected.")
            return False

        self.connections[message.sender] = addr
        self.sockets[addr] = client_socket

        if not self.database.has(message.sender):
            debug(f"{message.sender} ({addr}) sent a status request, User is currently not registered.")
            self.send(message.sender, {"status": "NOT_REGISTERED"}, STATUS)
        else:
            debug(f"{message.sender} ({addr}) sent a status request, answering with 'REGISTERED'.")
            self.send(message.sender, {"status": "REGISTERED"}, STATUS)
        return True


if __name__ == "__main__":
    server = Server()
    server.start()
