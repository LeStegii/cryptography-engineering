import socket
import socket
import ssl

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat, PrivateFormat, \
    NoEncryption
from ecdsa.ellipticcurve import Point

import utils
from homework2.lecture3.tls.HKDF import hkdf_extract, hkdf_expand
from homework3.Database import Database
from homework3.lecture9.l9_utils import H, power, h, KDF, AKE_KeyGen, AEAD_encode, random_z_q, HMQV_KServer

key = None

database = Database("database.csv", "key.txt")


def start_ssl_server(host="localhost", port=12345, certfile="server.pem", keyfile="server.key"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}")
    with context.wrap_socket(server_socket, server_side=True) as ssock:
        conn, addr = ssock.accept()

        username = utils.decode_message(receive_message(conn))["username"]

        if database.get(username) is None:
            print(f"User {username} not found, sending registration request.")
            send_message(conn, utils.encode_message({"status": "NOT_REGISTERED"}))
            pw = utils.decode_message(receive_message(conn))["password"]

            if pw is None or len(pw) < 1:
                print("Received empty password.")
                conn.close()
                return

            s = random_z_q()
            rw = H(pw.encode() + power(h(pw.encode()), s).to_bytes())
            rw_key = KDF(rw)
            lpk_c, lsk_c = AKE_KeyGen()
            lpk_s, lsk_s = AKE_KeyGen()
            client_key_info = {"lpk_c": lpk_c, "lsk_c": lsk_c, "lpk_s": lpk_s}
            iv, enc_client_keys, tag = AEAD_encode(rw_key, utils.encode_message(client_key_info))
            database.insert(username, {
                "s": s,
                "server_key_bundle": {
                    "lpk_c": lpk_c,
                    "lpk_s": lpk_s,
                    "lsk_s": lsk_s
                },
                "enc_client_keys": enc_client_keys,
                "iv": iv,
                "tag": tag
            })

            print(f"User {username} registered.")
        else:
            print(f"User {username} found, sending registration confirmation.")
            send_message(conn, utils.encode_message({"status": "REGISTERED"}))

        print("Waiting for login request...")

        h_pw_a: Point = utils.decode_message(receive_message(conn))["h_pw_a"]

        user_data = database.get(username)

        h_pw_a_s = power(h_pw_a, user_data["s"])

        send_message(conn, utils.encode_message({
            "h_pw_a_s": h_pw_a_s,
            "enc_client_keys": user_data["enc_client_keys"],
            "iv": user_data["iv"],
            "tag": user_data["tag"]
        }))

        server_k_bundle = user_data["server_key_bundle"]  # (lpk_c, lpk_s, lsk_s)

        if utils.decode_message(receive_message(conn))["status"] == "TAG_INVALID":
            print("Invalid tag, password of client was probably incorrect.")
            return

        # AKE
        b = server_k_bundle["lsk_s"]
        A = server_k_bundle["lpk_c"]
        Y, y = AKE_KeyGen()

        X = utils.decode_message(receive_message(conn))["X"]
        send_message(conn, utils.encode_message({"Y": Y}))

        SK = HMQV_KServer(b, y, Y, A, X, username, host)

        print("Shared secret generated: " + SK.hex())

        key = hkdf_expand(SK, b"key", 32 * 2)
        K_C, K_S = key[:32], key[32:]

        mac_c = utils.HMAC(K_C, b"Client KC")
        mac_s_1 = utils.HMAC(K_S, b"Server KC")

        send_message(conn, utils.encode_message({"mac_c": mac_c}))
        mac_s = utils.decode_message(receive_message(conn))["mac_s"]

        if mac_s != mac_s_1:
            print("Couldn't validate mac_s from client.")
            return

        print("SK accepted!")


def send_message(conn, message: bytes) -> None:
    conn.sendall(message)


def receive_message(conn) -> bytes:
    return conn.recv(4096)


if __name__ == "__main__":
    start_ssl_server()
