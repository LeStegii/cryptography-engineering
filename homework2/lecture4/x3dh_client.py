import socket
import ssl
import threading
import traceback
from typing import Optional

from ecdsa import SigningKey, VerifyingKey

from homework2.lecture4 import x3dh_utils
from utils import ecdsa_sign


class Client:
    def __init__(self, host="localhost", port=25566):
        self.host: str = host
        self.port: int = port
        self.client_socket: Optional[ssl.SSLSocket] = None

        self.username: Optional[str] = None

        self.ik: Optional[SigningKey] = None
        self.IPK: Optional[VerifyingKey] = None
        self.sk: Optional[SigningKey] = None
        self.SPK: Optional[VerifyingKey] = None
        self.oks: list[SigningKey] = []
        self.OPKs: list[VerifyingKey] = []
        self.sigma: Optional[bytes] = None

    def generate_keys(self):
        self.ik, self.IPK = x3dh_utils.generate_signature_key_pair()
        self.sk, self.SPK = x3dh_utils.generate_signature_key_pair()

        # Usually, there are multiple one-time keys and one-time public keys
        ok, OPK = x3dh_utils.generate_signature_key_pair()
        self.oks = [ok]
        self.OPKs = [OPK]

        self.sigma = ecdsa_sign(self.SPK.to_pem(), self.ik)

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

    def send(self, message: bytes):
        try:
            self.client_socket.send(message)
        except Exception:
            traceback.print_exc()
            print("Failed to send the message.")

    def receive_message(self):
        try:
            while True:
                message = self.client_socket.recv(1024)
                if message:
                    if message.startswith(b"REGISTERED"):
                        print("Successfully registered.")
                        continue

                    if message.startswith(b"ALREADY_REGISTERED"):
                        print("Failed to register. Username already taken.")
                        self.client_socket.close()
                        break

                else:
                    print("Connection closed by server.")
                    break
        except ConnectionResetError:
            traceback.print_exc()
            print("Connection was reset by the server.")
        except Exception:
            traceback.print_exc()
            print("Error receiving message.")

    def send_messages(self):
        """Handles user input and sends messages to the server."""
        try:
            while True:
                msg = input("Enter a message: ")
                if msg.lower() == "exit":
                    print("Closing connection.")
                    self.client_socket.close()
                    break
                self.send(msg.encode("utf-8"))
        except Exception:
            traceback.print_exc()
            print("Error sending messages.")

    def start(self):
        self.connect()

        self.username = input("Enter your username: ")

        print("Generating keys...")
        self.generate_keys()

        print("Sending registration request...")
        self.send_registration()

        receive_thread = threading.Thread(target=self.receive_message, daemon=True)
        receive_thread.start()

        self.send_messages()

    def send_registration(self):
        ipk_hex = self.IPK.to_pem().hex()
        spk_hex = self.SPK.to_pem().hex()
        opk_hex = self.OPKs[0].to_pem().hex()
        sigma_hex = self.sigma.hex()

        message = f"REGISTER   {self.username.encode().hex()}   {ipk_hex}   {spk_hex}   {sigma_hex}   {opk_hex}"
        self.send(message.encode("utf-8"))


if __name__ == "__main__":
    import sys

    HOST = "localhost" if len(sys.argv) < 3 else sys.argv[2]
    PORT = 25566 if len(sys.argv) < 4 else int(sys.argv[3])

    client = Client(HOST, PORT)
    client.start()
