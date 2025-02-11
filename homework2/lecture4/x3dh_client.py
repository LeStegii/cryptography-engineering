import socket
import ssl
import threading
import traceback
from pathlib import Path
from typing import Optional

from ecdsa import SigningKey, VerifyingKey

from homework2.lecture3.tls.HKDF import hkdf_extract
from homework2.lecture4 import x3dh_utils
from homework3.lecture8.client import username
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

        self.key_bundles: dict[str, dict[str, VerifyingKey | bytes]] = {}  # List of key bundles (username, keys)
        self.x3dh_keys: dict[str, bytes] = {}  # List of shared secrets (username, key)

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

                    if message["type"] == "X3DH_REACTION":
                        print(f"Received X3DH reaction from {message["sender"]}.")
                        self.reaction_x3dh(message)
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
        self.load_or_generate_keys()

        print("Sending registration request...")
        self.send_registration()

        receive_thread = threading.Thread(target=self.receive_message, daemon=True)
        receive_thread.start()

        self.send_messages()

    # X3DH METHODS

    def load_or_generate_keys(self):
        # Check if username.txt exists
        # If it does, load the keys from there
        # If it doesn't, generate the keys and save them to username.txt

        if Path(f"key-{self.username}.txt").exists():
            with open(f"key-{self.username}.txt", "r") as f:
                self.ik = SigningKey.from_pem(bytes.fromhex(f.readline()).decode())
                self.IPK = VerifyingKey.from_pem(bytes.fromhex(f.readline()).decode())
                self.sk = SigningKey.from_pem(bytes.fromhex(f.readline()).decode())
                self.SPK = VerifyingKey.from_pem(bytes.fromhex(f.readline()).decode())
                self.ok = SigningKey.from_pem(bytes.fromhex(f.readline()).decode())
                self.OPK = VerifyingKey.from_pem(bytes.fromhex(f.readline()).decode())
        else:
            self.ik, self.IPK = x3dh_utils.generate_signature_key_pair()
            self.sk, self.SPK = x3dh_utils.generate_signature_key_pair()
            # Usually, there are multiple one-time keys and one-time public keys
            self.ok, self.OPK = x3dh_utils.generate_signature_key_pair()

            with open(f"key-{self.username}.txt", "w") as f:
                f.write(self.ik.to_pem().hex() + "\n")
                f.write(self.IPK.to_pem().hex() + "\n")
                f.write(self.sk.to_pem().hex() + "\n")
                f.write(self.SPK.to_pem().hex() + "\n")
                f.write(self.ok.to_pem().hex() + "\n")
                f.write(self.OPK.to_pem().hex() + "\n")

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

    def x3dh_key(self, ik: SigningKey, ek: SigningKey, IPK_B: VerifyingKey, SPK_B: VerifyingKey, OPK_B: VerifyingKey):
        DH1 = x3dh_utils.power(ik, SPK_B)
        DH2 = x3dh_utils.power(ek, IPK_B)
        DH3 = x3dh_utils.power(ek, SPK_B)
        DH4 = x3dh_utils.power(ek, OPK_B)
        return hkdf_extract(salt=None, input_key_material=DH1 + DH2 + DH3 + DH4)

    def x3dh_key_reaction(self, IPK_A: VerifyingKey, EPK_A: VerifyingKey, ik: SigningKey, sk: SigningKey, ok: SigningKey):
        DH1 = x3dh_utils.power(sk, IPK_A)
        DH2 = x3dh_utils.power(ik, EPK_A)
        DH3 = x3dh_utils.power(sk, EPK_A)
        DH4 = x3dh_utils.power(ok, EPK_A)
        return hkdf_extract(salt=None, input_key_material=DH1 + DH2 + DH3 + DH4)

    def handle_key_receive(self, message: dict[str, str | dict[str, VerifyingKey | bytes]]) -> bool:

        owner = message["owner"]
        key_bundle = message["key_bundle"]

        IPK_B = key_bundle["IPK"]
        SPK_B = key_bundle["SPK"]
        sigma_B = key_bundle["sigma"]
        OPK_B = key_bundle["OPK"]

        print(f"Received X3DH key bundle from {owner}:")

        print("Checking signature...")
        if not ecdsa_verify(sigma_B, SPK_B.to_pem(), IPK_B):
            print("Signature verification failed.")
            return False
        print("Signature verified.")

        self.key_bundles[owner] = key_bundle

        print("Generating shared secret...")

        ek, EPK = x3dh_utils.generate_signature_key_pair()
        SK = self.x3dh_key(self.ik, ek, IPK_B, SPK_B, OPK_B)

        print("Shared secret generated: ", SK)

        self.x3dh_keys[owner] = SK

        iv, cipher, tag = x3dh_utils.aes_gcm_encrypt(SK, b"some message", self.IPK.to_pem() + IPK_B.to_pem())

        self.send(x3dh_utils.encode_message({
            "type": "X3DH_REACTION",
            "target": owner,
            "sender": self.username,
            "IPK": self.IPK,
            "EPK": EPK,
            "OPK": self.OPK,
            "aead": {
                "iv": iv,
                "cipher": cipher,
                "tag": tag
            }
        }))

        return True

    def reaction_x3dh(self, message):
        IPK_A = message["IPK"]
        EPK_A = message["EPK"]
        OPK_A = message["OPK"]

        iv = message["aead"]["iv"]
        cipher = message["aead"]["cipher"]
        tag = message["aead"]["tag"]

        SK = self.x3dh_key_reaction(IPK_A, EPK_A, self.ik, self.sk, self.ok)

        print("Shared secret generated: ", SK)

        try:
            plaintext = x3dh_utils.aes_gcm_decrypt(SK, iv, cipher, IPK_A.to_pem() + self.IPK.to_pem(), tag)
        except Exception:
            print("Failed to decrypt the message.")
            return

        if plaintext == b"some message":
            print(f"Successfully completed x3dh protocol with {message["sender"]}.")
        else:
            print("Failed to complete x3dh protocol.")


if __name__ == "__main__":
    import sys

    HOST = "localhost" if len(sys.argv) < 3 else sys.argv[2]
    PORT = 25566 if len(sys.argv) < 4 else int(sys.argv[3])

    client = Client(HOST, PORT)
    client.start()
