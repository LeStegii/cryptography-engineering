import socket
import socket
import ssl
from typing import Optional

from cryptography.hazmat.primitives._serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

import utils
from homework3.lecture8.scram_utils import H
from homework3.lecture9.l9_utils import H, random_element, h, power, inverse, KDF, AEAD_decode, random_z_q

username: Optional[str] = None
pw: Optional[str] = None


def start_ssl_client(host="localhost", port=12345, cafile="server.pem"):
    global username, pw
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile)

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print(f"Connected to {host}:{port}")

            send_message(ssock, utils.encode_message({"username": username}))

            status = utils.decode_message(receive_message(ssock))["status"]

            if status == "NOT_REGISTERED":
                print("User not registered. Please create a password.")
                pw = input("Enter your password: ")
                send_message(ssock, utils.encode_message({"password": pw}))
                print("Registration complete.")

            print("Trying to login...")
            pw = input("Enter your password: ")

            h_pw = h(pw.encode())
            a = random_z_q()
            h_pw_a = power(h_pw, a)

            send_message(ssock, utils.encode_message({"h_pw_a": h_pw_a}))

            login_answer = utils.decode_message(receive_message(ssock))

            h_pw_a_s = login_answer["h_pw_a_s"]
            enc_client_keys = login_answer["enc_client_keys"]
            iv = login_answer["iv"]
            tag = login_answer["tag"]

            a_inv = inverse(a)
            hp_pw_s = power(h_pw_a_s, a_inv)

            rw = H(pw.encode() + hp_pw_s.to_bytes())
            rw_key = KDF(rw)
            enc_client_key_info = AEAD_decode(rw_key, enc_client_keys, iv, tag)
            client_key_info = utils.decode_message(enc_client_key_info)

            lpk_c = client_key_info["lpk_c"]
            lsk_c = client_key_info["lsk_c"]
            lpk_s = client_key_info["lpk_s"]

        print("lpk_s: " + lpk_s.public_bytes(encoding=Encoding.PEM, format=PublicFormat.Raw).hex())
        print("lpk_c: " + lpk_c.public_bytes(encoding=Encoding.PEM, format=PublicFormat.Raw).hex())
        print("lsk_c: " + lsk_c.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()).hex())










def send_message(conn, message: bytes) -> None:
    conn.sendall(message)


def receive_message(conn) -> bytes:
    return conn.recv(4096)


if __name__ == "__main__":
    username = input("Enter your username: ")

    start_ssl_client()
