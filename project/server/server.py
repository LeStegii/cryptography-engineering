import datetime
import os
import socket
import ssl
import threading
import traceback
from ssl import SSLSocket
from typing import Optional

import project.server.handler.login_handler as login_handler
import project.server.handler.message_handler as message_handler
import project.server.handler.x3dh_handler as x3dh_handler
from project.server.handler import identity_handler, reset_handler
from project.util.serializer import serializer
from project.util.database import Database
from project.util.message import MESSAGE, Message, REGISTER, REQUEST_SALT, IDENTITY, LOGIN, X3DH_BUNDLE_REQUEST, X3DH_FORWARD, X3DH_REQUEST_KEYS, \
    is_valid_message, RESET
from project.util.utils import debug


class Server:
    def __init__(self, host: str = "localhost", port: int = 25567):
        self.host: str = host
        self.port: int = port
        self.server_socket: Optional[ssl.SSLSocket] = None
        self.sockets: dict[tuple[str, int], ssl.SSLSocket] = {}  # List of connected clients (addr, socket)
        self.connections: dict[str, tuple[str, int]] = {}  # List of connected clients (username, addr)

        self.database = Database("db/database.json")
        self.peppers = Database("db/peppers.csv", "db/server-key-peppers.txt", True)

        # Set all users to logged out (in case the server crashed)
        for user in self.database.keys():
            self.database.update(user, {"logged_in": False})

        self.login_attempts: dict[str, list[datetime.datetime]] = {}  # Dictionary to store login attempts

        # Handlers for different message types
        self.handlers: dict[str, any] = {
            REGISTER: login_handler.handle_register,
            LOGIN: login_handler.handle_login,
            REQUEST_SALT: login_handler.handle_request_salt,
            MESSAGE: message_handler.handle_message,
            X3DH_BUNDLE_REQUEST: x3dh_handler.handle_x3dh_bundle_request,
            X3DH_FORWARD: x3dh_handler.handle_x3dh_forward,
            X3DH_REQUEST_KEYS: x3dh_handler.handle_x3dh_key_shortage,
            RESET: reset_handler.handle_reset
        }

    def username(self, addr: tuple[str, int]) -> Optional[str]:
        """
        Returns the username of the client with the given address.
        :param addr: The address of the client
        :return: The username of the client or None if the client is not connected
        """
        for username, client_addr in self.connections.items():
            if client_addr == addr:
                return username
        return None

    def is_registered(self, username: str) -> bool:
        """
        Checks if the user with the given name is registered by checking if 'registered' is set to True.
        This should be the case after a user provided their identity, set a password and sent their keys.
        :param username: The name of the user
        :return: Whether the user is registered
        """
        return self.database.has(username) and self.database.get(username).get("registered") == True

    def is_logged_in(self, username: str) -> bool:
        """
        Checks if the user with the given name is currently logged in by checking if 'logged_in' is set to True.
        :param username: The name of the user
        :return: Whether the user is logged in
        """
        return self.database.has(username) and self.database.get(username).get("logged_in") == True

    def add_offline_message(self, username: str, message: Message):
        """
        Adds a message to the offline messages of the user with the given name.
        :param username: The name of the user
        :param message: The message to add
        """
        if self.is_registered(username):
            if "offline_messages" not in self.database.get(username):
                self.database.update(username, {"offline_messages": [message]})
            else:
                self.database.get(username).get("offline_messages").append(message)

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


    def check_too_many_attempts(self, username: str) -> bool:
        """
        Checks if the user with the given name has made too many login attempts in the last 5 minutes.
        :param username: The name of the user
        :return: Whether the user has made too many login attempts
        """
        if not self.login_attempts.get(username):
            return False

        for attempt in self.login_attempts.get(username, []):
            if attempt < datetime.datetime.now() - datetime.timedelta(minutes=5):
                self.login_attempts.get(username).remove(attempt)

        if len(self.login_attempts.get(username)) >= 3:
            return True
        return False

    def add_login_attempt(self, username: str):
        if not self.login_attempts.get(username):
            self.login_attempts[username] = []

        self.login_attempts.get(username).append(datetime.datetime.now())

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
                message=serializer.encode_message(content),
                sender="server",
                receiver=receiver if isinstance(receiver, str) else "unknown",
                type=type
            )
            self.send_bytes(message.to_bytes(), receiver)
        except Exception:
            traceback.print_exc()
            debug(f"Failed to send the message to {receiver}.")

    def handle_client(self, client_socket: ssl.SSLSocket, addr: tuple[str, int]):
        try:

            debug(f"Handling client {addr}. Checking it's identity.")
            if not identity_handler.check_identity(self, client_socket, addr):
                return

            username = self.username(addr)

            while True:
                received_bytes = client_socket.recv(8192)
                if not received_bytes:
                    debug(f"Received empty byte message from {addr}. Closing connection.")
                    break
                message = Message.from_bytes(received_bytes)

                # Check if message can be decoded and has valid fields
                if is_valid_message(message):

                    # Check if the user tries to send a message as another user
                    if not message.sender == username:
                        debug(f"{message.sender} ({addr}) tried to send a message as {username}.")
                        break

                    # Check if the user is logged in (except for messages required to log in)
                    if not self.is_logged_in(message.sender) and message.type not in [IDENTITY, REGISTER, LOGIN, REQUEST_SALT]:
                        debug(f"{message.sender} ({addr}) tried to send a message with type '{message.type}' without being logged in.")
                        break

                    # Only messages of type MESSAGE can be sent to other clients
                    if message.receiver != "server" and message.type != MESSAGE:
                        debug(f"{message.sender} ({addr}) tried to send a non-message type message to {message.receiver}.")
                        continue

                    # Execute the handler for the message type
                    handler = self.handlers.get(message.type, self.handle_unknown)
                    handler(self, message, client_socket, addr)
                else:
                    debug(f"Client {addr} sent an invalid message. Closing connection.")
                    break
        except Exception as e:
            debug(f"Error with client {addr}: {e}")
        finally:
            # Close connection and log out user
            client_socket.close()
            username = self.username(addr)
            if username:
                self.database.update(username, {"logged_in": False})
                self.connections.pop(username, None)
            self.sockets.pop(addr, None)
            debug(f"Connection with {addr} closed.")

    def handle_unknown(self, message: Message, client: SSLSocket, addr: tuple[str, int]):
        debug(f"{message.sender} ({addr}) sent message of unknown type '{message.type}'.")


if __name__ == "__main__":
    server = Server()
    server.start()
