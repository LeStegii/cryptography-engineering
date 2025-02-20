import socket
import ssl
import threading
import time
import traceback
from typing import Optional

import utils
from project.database import Database
from project.message import Message, MESSAGE, STATUS, REGISTER, LOGIN, IDENTITY, ANSWER_SALT, REQUEST_SALT, ERROR, \
    SUCCESS

enable_debug = True

class Client:
    def __init__(self, host="localhost", port=25567):
        self.host: str = host
        self.port: int = port
        self.client_socket: Optional[ssl.SSLSocket] = None

        self.username: Optional[str] = None
        self.database: Optional[Database] = None

    # CONNECTION METHODS

    def connect(self):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Wrap with SSL
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations("server.pem")
            self.client_socket = context.wrap_socket(raw_socket, server_hostname=self.host)

            self.client_socket.connect((self.host, self.port))
            print(f"Connected to server {self.host}:{self.port}.")
        except Exception as e:
            traceback.print_exc()
            print("Failed to connect to the server.")
            raise e

    def send(self, receiver: str, content: dict[str, any], type: str = MESSAGE):
        try:
            self.client_socket.send(
                Message(message=utils.encode_message(content), sender=self.username, receiver=receiver,
                        type=type).to_bytes())
        except Exception:
            traceback.print_exc()
            print("Failed to send the message.")

    def receive_message(self):
        try:
            while True:
                message_bytes = self.client_socket.recv(4096)
                if not message_bytes:
                    print("Connection closed.")
                    break
                message = Message.from_bytes(message_bytes)
                if message:
                    type = message.type
                    receiver = message.receiver
                    sender = message.sender
                    content = message.dict()

                    ####################################################################################################

                    if type == STATUS:
                        if content.get("status") == ERROR:
                            print(f"Received error from server: {content['error']}")
                        elif content.get("status") == "NOT_REGISTERED":
                            print("User not registered.")
                            password = input("Enter your new password: ")
                            self.send("server", {"password": password}, REGISTER)
                        elif content.get("status") == "REGISTERED":
                            print("User registered. Requesting salt from server...")
                            self.send("server", {"reason": "login"}, REQUEST_SALT)
                        else:
                            print(f"Received unknown status from server: {content['status']}")

                    ####################################################################################################

                    elif type == ANSWER_SALT:
                        salt = content.get("salt")
                        print(f"Received salt from server.")
                        self.database.insert(self.username, {"salt": salt})
                        password = input("Received salt for login. Please enter your password: ")
                        if not self.login(password):
                            print("Error logging in.")
                            break

                    ####################################################################################################

                    elif type == REGISTER:
                        if content.get("status") == SUCCESS:
                            salt = content.get("salt")
                            self.database.insert(self.username, {"salt": salt})
                            print(f"Received salt from server.")
                            print("User registered successfully. You can now login.")
                            password = input("Enter your password: ")
                            if not self.login(password):
                                print("Error logging in.")
                                break
                        elif content.get("status") == ERROR:
                            print("Error registering user. User might already exist or messages are not in order.")
                            break

                    ####################################################################################################

                    elif type == LOGIN:
                        if content.get("status") == SUCCESS:
                            print("User logged in successfully.")
                            self.send_messages()
                        elif content.get("status") == ERROR:
                            print("Error logging in. Password might be incorrect.")
                            break

                else:
                    print("Connection closed by server.")
                    break
        except (ConnectionResetError, OSError):
            print("Connection closed.")
        except Exception:
            traceback.print_exc()
            print("Error receiving message.")
        finally:
            if self.client_socket:
                self.client_socket.close()

    def send_messages(self):
        try:
            print("\n\nYou can now send messages to the server.")
            print("Type 'exit' to close the connection.")
            while True:
                msg = input()
                if msg.lower() == "exit":
                    print("Closing connection.")
                    self.client_socket.close()
                    break


        except Exception:
            traceback.print_exc()
            print("Error sending messages.")

    def start(self):
        self.connect()

        self.username = input("Enter your username: ")
        print(f"Connected to server {self.host}:{self.port} as {self.username}.")

        self.database = Database(f"{self.username}-db.csv", f"{self.username}-key.txt")

        receive_thread = threading.Thread(target=self.receive_message, daemon=True)
        receive_thread.start()

        time.sleep(0.1)
        self.send("server", {"username": self.username}, IDENTITY) # Send the identity message to the server

        # Wait for the receive thread to finish
        receive_thread.join()

    def login(self, password: str) -> bool:
        salt = self.database.get(self.username).get("salt")
        if not salt:
            print("Salt not found in database. This should not happen. Please request it again.")
            return False
        salted_password = utils.salt_password(password, self.database.get(self.username).get("salt"))
        self.send("server", {"salted_password": salted_password}, LOGIN)
        return True

def debug(message: str):
    if __debug__:
        print(f"DEBUG: {message}")

if __name__ == "__main__":
    client = Client()
    client.start()
