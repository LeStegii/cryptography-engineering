import select
import socket
import ssl
import threading
import time
import traceback
from typing import Optional

from ecdsa import SigningKey, VerifyingKey

from project.client.handler import login_handler, message_handler, x3dh_handler
from project.util import x3dh_utils, crypto_utils
from project.util.crypto_utils import power_sk_vk, KDF
from project.util.database import Database
from project.util.message import Message, MESSAGE, REGISTER, LOGIN, IDENTITY, ANSWER_SALT, STATUS, X3DH_BUNDLE_REQUEST, X3DH_FORWARD, X3DH_REQUEST_KEYS, \
    is_valid_message
from project.util.serializer.serializer import encode_message
from project.util.utils import debug

enable_debug = True


class Client:
    def __init__(self, host="localhost", port=25567):
        self.host: str = host
        self.port: int = port
        self.client_socket: Optional[ssl.SSLSocket] = None
        self.receive_thread: Optional[threading.Thread] = None
        self.send_thread: Optional[threading.Thread] = None

        self.username: Optional[str] = None
        self.database: Optional[Database] = None

        self.handlers: dict[str, any] = {
            REGISTER: login_handler.handle_register,
            STATUS: login_handler.handle_status,
            LOGIN: login_handler.handle_login,
            ANSWER_SALT: login_handler.handle_answer_salt,
            MESSAGE: message_handler.handle_message,
            X3DH_BUNDLE_REQUEST: x3dh_handler.handle_x3dh_bundle_answer,
            X3DH_FORWARD: x3dh_handler.handle_x3dh_forward,
            X3DH_REQUEST_KEYS: x3dh_handler.handle_x3dh_key_request
        }

        # Add event to signal when to stop threads
        self.stop_event = threading.Event()

    # CONNECTION METHODS

    def connect(self):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Wrap with SSL
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations("server.pem")
            self.client_socket = context.wrap_socket(raw_socket, server_hostname=self.host)

            self.client_socket.connect((self.host, self.port))
            debug(f"Connected to server {self.host}:{self.port}.")
        except Exception as e:
            traceback.print_exc()
            debug("Failed to connect to the server.")
            raise e

    def send(self, receiver: str, content: dict[str, any], type: str = MESSAGE):
        try:
            self.client_socket.send(
                Message(message=encode_message(content), sender=self.username, receiver=receiver,
                        type=type).to_bytes())
        except Exception:
            traceback.print_exc()
            debug("Failed to send the message.")

    def receive_message(self):
        try:
            while not self.stop_event.is_set():  # Check if stop event is triggered
                # Use select to check if data is available to read on the socket
                readable, _, _ = select.select([self.client_socket], [], [], 1.0)  # 1 second timeout
                if readable:
                    message_bytes = self.client_socket.recv(8096)
                    if not message_bytes:
                        debug("Connection closed.")
                        break
                    message = Message.from_bytes(message_bytes)
                    if is_valid_message(message):
                        type = message.type
                        handler = self.handlers.get(type, self.handle_unknown)
                        if not handler(self, message):
                            break
                    else:
                        debug("Server sent invalid message! Closing connection.")
                        break
        except (ConnectionResetError, OSError):
            debug("Connection closed.")
        except Exception:
            traceback.print_exc()
            debug("Error receiving message.")
        finally:
            if self.client_socket:
                self.client_socket.close()

    def send_messages(self):
        try:
            debug("You can now send messages to the server.")
            debug("Type 'exit' to close the connection.")
            debug("Type 'x3dh <target>' to initiate a key exchange.")
            debug("Type 'msg <target> <message>' to chat.")
            while True:
                msg = input()
                if msg.lower() == "exit":
                    debug("Closing connection.")
                    self.stop_event.set()  # Signal the receive thread to stop
                    self.client_socket.close()
                    break

                split = msg.split(" ")
                if len(split) >= 2 and split[0].strip() and split[1].strip():
                    type = split[0]
                    receiver = split[1]
                    if receiver == self.username:
                        debug("You cannot send messages to yourself.")
                        continue

                    if type == "x3dh":
                        debug(f"Requesting key bundle for {receiver}...")
                        self.send("server", {"target": receiver}, X3DH_BUNDLE_REQUEST)

                    elif type == "msg" or type == "message" or type == "send" and len(split) > 3:
                        text = " ".join(split[2:])
                        if not text or len(text.strip()) == 0:
                            debug("Empty messages aren't allowed.")
                            continue
                        if not self.database.get("shared_secrets") or not self.database.get("shared_secrets").get(receiver):
                            debug(f"{receiver} is not in the database, request their key bundle first!")
                            continue

                        if not self.database.has("chats"):
                            self.database.insert("chats", {})

                        chat = self.database.get("chats").get(receiver, [])
                        if not chat:
                            self.database.insert("chats", {receiver: chat})

                        index = len(chat)

                        if index == 0:
                            x, X = crypto_utils.generate_signature_key_pair()
                            Y = self.database.get("key_bundles").get(receiver).get("SPK")  # Receiver's Signed PreKey
                            ck = self.database.get("shared_secrets").get(receiver)
                            DH = power_sk_vk(x, Y)  # Compute initial Diffie-Hellman

                            chat.append({"X": X, "last": "ME", "ck": ck, "Y": Y, "x": x})  # Store state

                        elif chat[-1].get("last") == "ME":
                            # Continue message chain (no DH change)
                            DH = b"\x00" * 32  # No new DH step
                            x, X = chat[-1].get("X")
                            ck = chat[-1].get("ck")

                        else:
                            # New ratchet step: Perform DH exchange
                            DH = power_sk_vk(chat[-1].get("x"), chat[-1].get("Y"))
                            x, X = crypto_utils.generate_signature_key_pair()
                            ck = chat[-1].get("ck")

                        # Key derivation for encryption
                        ck1, mk1 = KDF(DH, ck)

                        # Encrypt message
                        iv, cipher, tag = crypto_utils.aes_gcm_encrypt(mk1, text.encode(), self.username.encode())

                        # Store updated state
                        chat.append({"X": X, "last": "ME", "ck": ck1, "Y": chat[-1].get("Y"), "x": x})
                        self.database.insert("chats", {receiver: chat})

                        # Send message
                        self.send(receiver, {"X": X, "cipher": cipher, "iv": iv, "tag": tag}, MESSAGE)
                else:
                    debug("Invalid message format. Please enter in the format '<type> <receiver> [<message>]'.")

        except Exception:
            traceback.print_exc()
            debug("Error sending messages.")

    def start(self):
        self.connect()

        self.username = input("Enter your username: ")
        debug(f"Connected to server {self.host}:{self.port} as {self.username}.")

        self.database = Database(f"db/{self.username}/database.json", f"db/{self.username}/key.txt")

        self.receive_thread = threading.Thread(target=self.receive_message, daemon=True)
        self.receive_thread.start()

        time.sleep(0.1)
        self.send("server", {"username": self.username}, IDENTITY)  # Send the identity message to the server

        # Wait for the threads to finish
        if self.receive_thread:
            self.receive_thread.join()
        if self.send_thread:
            self.send_thread.join()

    def handle_unknown(self, message: Message):
        debug(f"{message.sender} sent message of unknown type '{message.type}'. Closing connection to be safe.")
        return False

    def load_or_gen_keys(self) -> dict[str, SigningKey, VerifyingKey]:
        keys = self.database.get("keys")
        if not keys:
            keys = x3dh_utils.generate_initial_x3dh_keys()
            self.database.insert("keys", keys)
        return keys


if __name__ == "__main__":
    client = Client()
    client.start()
