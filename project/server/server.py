import os
import socket
import ssl
import threading
import traceback
from ssl import SSLSocket
from typing import Optional

import utils
from project.database import Database
from project.message import MESSAGE, Message, STATUS, REGISTER, REQUEST_SALT, ANSWER_SALT, IDENTITY, LOGIN, ERROR, \
    SUCCESS, REGISTERED, NOT_REGISTERED, X3DH_BUNDLE_REQUEST, X3DH_FORWARD, X3DH_REQUEST_KEYS
from project.project_utils import is_valid_message, debug, check_username
import project.server.handler.x3dh_handler as x3dh_handler
import project.server.handler.login_handler as login_handler
import project.server.handler.message_handler as message_handler


class Server:
    def __init__(self, host: str = "localhost", port: int = 25567):
        self.host: str = host
        self.port: int = port
        self.server_socket: Optional[ssl.SSLSocket] = None
        self.sockets: dict[tuple[str, int], ssl.SSLSocket] = {}  # List of connected clients (addr, socket)
        self.connections: dict[str, tuple[str, int]] = {}  # List of connected clients (username, addr)

        self.database = Database("db/database.json", "db/server-key.txt")

        # Set all users to logged out (in case the server crashed)
        for user in self.database.keys():
            self.database.update(user, {"logged_in": False})

        self.handlers: dict[str, any] = {
            REGISTER: login_handler.handle_register,
            LOGIN: login_handler.handle_login,
            REQUEST_SALT: login_handler.handle_request_salt,
            MESSAGE: message_handler.handle_message,
            X3DH_BUNDLE_REQUEST: x3dh_handler.handle_x3dh_bundle_request,
            X3DH_FORWARD: x3dh_handler.handle_x3dh_forward,
            X3DH_REQUEST_KEYS: x3dh_handler.handle_x3dh_key_shortage
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
            debug(f"Client {recipient if not isinstance(recipient, SSLSocket) else recipient.getpeername()} not found.")
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

    def is_logged_in(self, username: str) -> bool:
        return self.database.has(username) and self.database.get(username).get("logged_in") == True

    def add_offline_message(self, username: str, message: Message):
        if self.is_registered(username):
            if "offline_messages" not in self.database.get(username):
                self.database.update(username, {"offline_messages": [message]})
            else:
                self.database.get(username).get("offline_messages").append(message)

    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple[str, int]):
        try:

            debug(f"Handling client {addr}. Checking it's identity.")
            if not self.check_identity(client_socket, addr):
                return

            username = self.username(addr)

            while True:
                received_bytes = client_socket.recv(8192)
                if not received_bytes:
                    debug(f"Received empty message from {addr}. Closing connection.")
                    break
                message = Message.from_bytes(received_bytes)

                if is_valid_message(message):

                    if not message.sender == username:
                        debug(f"{message.sender} ({addr}) tried to send a message as {username}.")
                        break

                    if not self.is_logged_in(message.sender) and message.type not in [IDENTITY, REGISTER, LOGIN, REQUEST_SALT]:
                        debug(f"{message.sender} ({addr}) tried to send a message with type '{message.type}' without being logged in.")
                        break

                    type = message.type
                    if message.type:

                        if message.receiver != "server" and type != MESSAGE:
                            debug(
                                f"{message.sender} ({addr}) tried to send a non-message type message to {message.receiver}.")
                            continue

                        handler = self.handlers.get(type, self.handle_unknown)
                        handler(self, message, client_socket, addr)
                    continue
                else:
                    debug(f"Client {addr} sent an invalid message. Closing connection.")
                    break
        except Exception as e:
            traceback.print_exc()
            debug(f"Error with client {addr}: {e}")
        finally:
            client_socket.close()
            username = self.username(addr)
            if username:
                self.database.update(username, {"logged_in": False})
                self.connections.pop(username, None)
            self.sockets.pop(addr, None)
            debug(f"Connection with {addr} closed.")



    def handle_unknown(self, message: Message, client: SSLSocket, addr: tuple[str, int]):
        debug(f"{message.sender} ({addr}) sent message of unknown type '{message.type}'.")


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

        if not self.is_registered(username):
            debug(f"{message.sender} ({addr}) sent a status request, User is currently not registered.")
            self.send(message.sender, {"status": NOT_REGISTERED}, STATUS)
        else:
            debug(f"{message.sender} ({addr}) sent a status request, User is registered.")
            self.send(message.sender, {"status": REGISTERED}, STATUS)
        return True


if __name__ == "__main__":
    server = Server()
    server.start()
