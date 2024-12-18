import socket
import ssl
import threading
import traceback
from typing import Optional

from ecdsa import SigningKey, VerifyingKey

from homework2.lecture4 import x3dh_utils
from utils import ecdsa_sign, ecdsa_verify


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
        self.ok: Optional[SigningKey] = None
        self.OPK: Optional[VerifyingKey] = None
        self.sigma: Optional[bytes] = None

        self.key_bundles: dict[bytes, dict[str, VerifyingKey | bytes]] = {}  # List of key bundles (username, keys)

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

    def send(self, message: bytes):
        try:
            self.client_socket.send(message)
        except Exception:
            traceback.print_exc()
            print("Failed to send the message.")

    def receive_message(self):
        try:
            while True:
                message = self.client_socket.recv(4096)
                if message:

                    message = x3dh_utils.decode_message(message)

                    if message["type"] == "REGISTERED":
                        print("Successfully registered.")
                        continue

                    if message["type"] == "ALREADY_REGISTERED":
                        print("Failed to register. Username already taken.")
                        break

                    if message["type"] == "X3DH_KEY":
                        if message["status"] != "SUCCESS" or not self.handle_key_receive(message):
                            print("Failed to receive key.")
                            continue
                        print("Received key bundle from server.")
                        continue

                else:
                    print("Connection closed by server.")
                    break
        except ConnectionResetError:
            traceback.print_exc()
            print("Connection was reset by the server.")
        except Exception:
            traceback.print_exc()
            print("Error receiving message.")
        finally:
            print("Closing connection.")
            self.client_socket.close()

    def send_messages(self):
        try:
            print("\n\nYou can now send messages to the server.")
            print("Type 'exit' to close the connection.")
            print("Type 'x3dh USER' to perform the X3DH key exchange.")
            while True:
                msg = input()
                if msg.lower() == "exit":
                    print("Closing connection.")
                    self.client_socket.close()
                    break

                if msg.startswith("x3dh"):
                    if len(msg.split()) != 2 or not msg.split()[1]:
                        print("Invalid format. Use 'x3dh USER'.")
                        continue
                    print(f"Initiating X3DH key exchange by requesting key of {msg.split(" ")[1]}...")
                    self.init_x3dh(msg.split()[1])
                    continue

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

    # X3DH METHODS

    def generate_keys(self):
        self.ik, self.IPK = x3dh_utils.generate_signature_key_pair()
        self.sk, self.SPK = x3dh_utils.generate_signature_key_pair()
        # Usually, there are multiple one-time keys and one-time public keys
        self.ok, self.OPK = x3dh_utils.generate_signature_key_pair()

        self.sigma = ecdsa_sign(self.SPK.to_pem(), self.ik)

    def send_registration(self):
        self.send(x3dh_utils.encode_message({
            "type": "REGISTER",
            "username": self.username,
            "IPK": self.IPK,
            "SPK": self.SPK,
            "sigma": self.sigma,
            "OPK": self.OPK
        }))

    def init_x3dh(self, target: str):
        self.send(x3dh_utils.encode_message({
            "type": "X3DH_REQUEST",
            "target": target
        }))

    def handle_key_receive(self, message: dict[str, bytes | dict[str, VerifyingKey | bytes]]) -> bool:

        owner = message["owner"]
        key_bundle = message["key_bundle"]

        IPK_B = key_bundle["IPK"]
        SPK_B = key_bundle["SPK"]
        sigma_B = key_bundle["sigma"]

        print(f"Received X3DH key bundle from {owner}:")

        print("Checking signature...")
        if not ecdsa_verify(sigma_B, SPK_B.to_pem(), IPK_B):
            print("Signature verification failed.")
            return False
        print("Signature verified.")

        self.key_bundles[owner] = key_bundle
        return True


if __name__ == "__main__":
    import sys

    HOST = "localhost" if len(sys.argv) < 3 else sys.argv[2]
    PORT = 25566 if len(sys.argv) < 4 else int(sys.argv[3])

    client = Client(HOST, PORT)
    client.start()
