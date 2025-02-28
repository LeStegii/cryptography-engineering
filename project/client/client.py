import select
import socket
import ssl
import threading
import time
import traceback
from typing import Optional

from ecdsa import SigningKey, VerifyingKey

from project.util import x3dh_utils, crypto_utils
from project.util.database import Database
from project.util.message import Message, MESSAGE, REGISTER, LOGIN, IDENTITY, ANSWER_SALT, REQUEST_SALT, ERROR, \
    SUCCESS, STATUS, NOT_REGISTERED, REGISTERED, X3DH_BUNDLE_REQUEST, X3DH_FORWARD, X3DH_REQUEST_KEYS, is_valid_message
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
            REGISTER: self.handle_register,
            STATUS: self.handle_status,
            LOGIN: self.handle_login,
            ANSWER_SALT: self.handle_answer_salt,
            MESSAGE: self.handle_message,
            X3DH_BUNDLE_REQUEST: self.handle_x3dh_bundle_answer,
            X3DH_FORWARD: self.handle_x3dh_forward,
            X3DH_REQUEST_KEYS: self.handle_x3dh_key_request
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
                        if not handler(message):
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
                        else:
                            debug(f"Sending message {text}...") # TODO
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

    def login(self, password: str) -> bool:
        salt = self.database.get("salt")
        if not salt:
            debug("Salt not found in database. This should not happen. Please request it again.")
            return False
        salted_password = crypto_utils.salt_password(password, self.database.get("salt"))
        self.send("server", {"salted_password": salted_password}, LOGIN)
        return True

    def handle_status(self, message: Message) -> bool:
        content = message.dict()
        if content.get("status") == ERROR:
            debug(f"Received error from server: {content.get('error')}")
            return False
        elif content.get("status") == NOT_REGISTERED:
            debug("User not registered.")
            password = input("Enter your new password: ")
            debug("Computing keys...")
            keys = self.load_or_gen_keys()
            key_bundle = {
                "IPK": keys["IPK"],
                "SPK": keys["SPK"],
                "OPKs": keys["OPKs"],
                "sigma": keys["sigma"]
            }
            debug("Sending registration request to server...")
            self.send("server", {"password": password, "keys": key_bundle}, REGISTER)
        elif content.get("status") == REGISTERED:
            debug("User registered. Requesting salt from server...")
            self.send("server", {}, REQUEST_SALT)
        else:
            debug(f"Received unknown status from server: {content.get('status')}")
            return False
        return True

    def handle_register(self, message: Message) -> bool:
        if message.dict().get("status") == SUCCESS:
            salt = message.dict().get("salt")
            self.database.insert("salt", salt)
            debug(f"Received salt from server.")
            debug("User registered successfully. You can now login.")
            password = input("Enter your password: ")
            if not self.login(password):
                debug("Error logging in.")
                return False
        elif message.dict().get("status") == ERROR:
            debug("Error registering user: " + message.dict().get("error"))
            return False
        return True

    def handle_login(self, message: Message) -> bool:
        if message.dict().get("status") == SUCCESS:
            debug("User logged in successfully.")
            # Execute the send_messages function in a new thread
            self.send_thread = threading.Thread(target=self.send_messages, daemon=True)
            self.send_thread.start()
        elif message.dict().get("status") == ERROR:
            debug("Error logging in. Password might be incorrect.")
            return False
        return True

    def handle_answer_salt(self, message: Message) -> bool:
        salt = message.dict().get("salt")
        self.database.insert("salt", salt)
        password = input("Received salt for login. Please enter your password: ")
        if not self.login(password):
            debug("Error logging in.")
            return False
        return True

    def handle_message(self, message: Message) -> bool:
        if not is_valid_message(message):
            debug(f"Received invalid message from {message.sender}.")

        if message.sender == "server":
            if message.dict().get("status") == ERROR:
                debug(f"Error from server: {message.dict().get('error')}")
            else:
                debug(f"Server: {message.dict().get('message')}")
            return True

        content = message.dict().get("message")
        if not content:
            debug(f"Received empty message from {message.sender}.")
        else:
            debug(f"{message.sender}: {content}")
        return True

    def handle_x3dh_bundle_answer(self, message: Message) -> bool:
        """
        Called after receiving a key bundle from the server.
        The key bundle is received after requesting it from the server.
        """
        content = message.dict()

        if content.get("status") == ERROR:
            debug(f"Failed to request key bundle: {content.get("error")}")
            return True

        key_bundle_b = content.get("key_bundle")
        if not key_bundle_b:
            debug(f"Received invalid key bundle for {content.get("owner")} from server.")
            return True

        keys = self.load_or_gen_keys()
        ik_A: SigningKey = keys["ik"]
        IPK_A: VerifyingKey = keys["IPK"]
        OPK_A: VerifyingKey = keys["OPKs"][0]

        sigma_B: bytes = key_bundle_b.get("sigma")
        IPK_B: VerifyingKey = key_bundle_b.get("IPK")
        SPK_B: VerifyingKey = key_bundle_b.get("SPK")
        OPK_B: VerifyingKey = key_bundle_b.get("OPK")

        if not crypto_utils.ecdsa_verify(sigma_B, SPK_B.to_pem(), IPK_B):
            debug("Invalid signature for SPK_B. Aborting X3DH.")
        else:
            debug("Computing shared secret...")
            ek_A, EPK_A = crypto_utils.generate_signature_key_pair()
            shared_secret = x3dh_utils.x3dh_key(ik_A, ek_A, IPK_B, SPK_B, OPK_B)
            self.database.update("shared_secrets", {content.get("owner"): shared_secret})
            debug("Sending reaction to server...")
            debug(f"Shared secret computed and saved for {content.get('owner')}: {shared_secret.hex()}")
            iv, cipher, tag = crypto_utils.aes_gcm_encrypt(shared_secret, self.username.encode(), IPK_A.to_pem() + IPK_B.to_pem())
            self.send("server", {
                "target": content.get("owner"),
                "IPK": IPK_A,
                "EPK": EPK_A,
                "OPK": OPK_A,
                "iv": iv,
                "cipher": cipher,
                "tag": tag
            }, X3DH_FORWARD)

        return True

    def handle_x3dh_forward(self, message: Message) -> bool:
        content = message.dict()
        debug(f"Received a forwarded x3dh message for {content.get('target')} from server.")

        keys = self.load_or_gen_keys()
        ik_B: SigningKey = keys["ik"]
        sk_B: SigningKey = keys["sk"]
        ok_B: SigningKey = keys["oks"][0]
        IPK_B: VerifyingKey = keys["IPK"]
        IPK_A: VerifyingKey = content.get("IPK")
        EPK_A: VerifyingKey = content.get("EPK")
        OPK_A: VerifyingKey = content.get("OPK")
        iv: bytes = content.get("iv")
        cipher: bytes = content.get("cipher")
        tag: bytes = content.get("tag")
        sender: str = content.get("sender")
        keys.get("oks").pop(0)
        keys.get("OPKs").pop(0)
        self.database.save()
        if len(keys.get("oks")) == 0:
            debug("No more one time prekeys left.")

        shared_secret = x3dh_utils.x3dh_key_reaction(IPK_A, EPK_A, ik_B, sk_B, ok_B)
        try:
            decrypted = crypto_utils.aes_gcm_decrypt(shared_secret, iv, cipher, IPK_A.to_pem() + IPK_B.to_pem(), tag)
            if decrypted == sender.encode():
                debug(f"Succesfully computed shared secret with {sender}: {shared_secret.hex()}")
                self.database.update("shared_secrets", {sender: shared_secret})
            else:
                debug(f"Failed to decrypt message from {sender}. Generating shared secret failed.")

            return True
        except Exception as e:
            debug(f"Failed to decrypt message from {sender}. Generating shared secret failed.")
            return True

    def handle_x3dh_key_request(self, message: Message) -> bool:
        """Called when the server doesn't have one time prekeys for the user."""

        if message.dict().get("status") == ERROR:
            debug("Failed to request key bundle from server.")
            return True
        elif message.dict().get("status") == SUCCESS:
            debug("Server accepted new one time prekeys.")
            return True

        keys = crypto_utils.generate_one_time_pre_keys(5)
        oks = [ok for ok, _ in keys]

        OPKs = [OPK for _, OPK in keys]

        self.load_or_gen_keys()["OPKs"].extend(OPKs)
        self.load_or_gen_keys()["oks"].extend(oks)
        self.send("server", {"OPKs": OPKs}, X3DH_REQUEST_KEYS)
        self.database.save()
        return True

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
