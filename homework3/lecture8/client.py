import os
import socket
import ssl
from typing import Optional

import utils
from homework3.lecture8.scram_utils import H, HMAC, sha256, xor_bytes

username: Optional[str] = None
password: Optional[str] = None


def start_ssl_client(host="localhost", port=12345, cafile="server.pem"):
    global username, password
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile)

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print(f"Connected to {host}:{port}")

            tls_info = {
                "version": "TLS"
            }

            print("Sending username...")

            send_message(ssock, utils.encode_message({"username": username}))

            print("Waiting for response...")

            status = utils.decode_message(receive_message(ssock))["status"]

            if status == "NOT_REGISTERED":
                print("User not registered, server requests password.")
                password = input("Enter your password: ")
                send_message(ssock, utils.encode_message({"password": password}))
                print("Password sent.")
            else:
                password = input("Enter your password: ")

            print("Server accepted the connection.")
            print("Sending challenge...")

            ch_1 = os.urandom(32)
            client_first = utils.encode_message({"username": username, "ch_1": ch_1})
            send_message(ssock, client_first)

            print("Challenge sent. Waiting for server response...")

            server_first = utils.decode_message(receive_message(ssock))
            ch_2 = server_first["ch_2"]
            r = server_first["r"]
            n = server_first["n"]

            print("Received server response. Computing proof...")

            salted_pw = H(n, password, r)
            client_key = HMAC(salted_pw, b"Client key")
            auth_msg = username.encode() + ch_1 + ch_2 + r + n.to_bytes(32, "big") + utils.encode_message(tls_info)
            client_sign = HMAC(sha256(client_key), auth_msg)
            client_proof = xor_bytes(client_key, client_sign)

            print("Proof computed. Sending to server...")

            client_final = utils.encode_message({
                "tls_info": tls_info,
                "ch_1": ch_1,
                "ch_2": ch_2,
                "client_proof": client_proof
            })

            send_message(ssock, client_final)

            print("Proof sent. Waiting for server response...")

            server_final = utils.decode_message(receive_message(ssock))

            if server_final["status"] == "SUCCESS":
                print("Server accepted the proof.")
                server_sign = server_final["server_sign"]
                print("Verifying server signature...")
                server_key = HMAC(salted_pw, b"Client key")
                auth_msg = username.encode() + ch_1 + ch_2 + r + n.to_bytes(32, "big") + utils.encode_message(tls_info)
                server_sign_calc = HMAC(server_key, auth_msg)

                if server_sign == server_sign_calc:
                    print("Server signature verified. Connection established.")
                    print("Sending success message...")
                    send_message(ssock, utils.encode_message({"status": "SUCCESS"}))
                else:
                    print("Server signature verification failed. Exiting.")
                    send_message(ssock, utils.encode_message({"status": "FAILED"}))
                    return

            else:
                print("Server rejected the proof. Exiting.")
                return



def send_message(conn, message: bytes) -> None:
    conn.sendall(message)


def receive_message(conn) -> bytes:
    return conn.recv(4096)


if __name__ == "__main__":
    username = input("Enter your username: ")

    start_ssl_client()
