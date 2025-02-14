import csv
import os
import random
import socket
import ssl
from pathlib import Path

import utils
from homework3.lecture8.scram_utils import H, HMAC, xor_bytes, sha256

key = None

# username -> (r, n, h_n)
database = {

}

currently_blocked = {}


def start_ssl_server(host="localhost", port=12345, certfile="server.pem", keyfile="server.key"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}")
    with context.wrap_socket(server_socket, server_side=True) as ssock:
        conn, addr = ssock.accept()

        tls_info = {
            "version": "TLS"
        }

        print(f"Connection established with {addr}")

        print("Waiting for login...")
        username = utils.decode_message(receive_message(conn))["username"]
        print(f"Received username: {username}")

        if username not in database:
            print("User not registered, requesting password.")
            send_message(conn, utils.encode_message({"status": "NOT_REGISTERED"}))
            print("Waiting for password...")
            password = utils.decode_message(receive_message(conn))["password"]
            print("Received password.")

            r = os.urandom(32)
            n = random.randint(1024, 4096)

            h_n = H(n, password, r)

            database[username] = (r, n, h_n)
            save_passwords("passwords.csv")

        else:
            print("User already registered.")
            send_message(conn, utils.encode_message({"status": "REGISTERED"}))

        ch_1 = utils.decode_message(receive_message(conn))["ch_1"]
        print(f"Received challenge: {ch_1}")

        print("Sending challenge response...")
        ch_2 = os.urandom(32)

        server_first = {
            "ch_1": ch_1,
            "ch_2": ch_2,
            "r": database[username][0],
            "n": database[username][1]
        }


        send_message(conn, utils.encode_message(server_first))

        print("Waiting for proof...")

        client_final = utils.decode_message(receive_message(conn))
        client_proof = client_final["client_proof"]

        print("Received proof. Verifying...")

        r = database[username][0]
        n = database[username][1]
        salted_pw = database[username][2]

        client_key = HMAC(salted_pw, b"Client key")
        auth_msg = username.encode() + ch_1 + ch_2 + r + n.to_bytes(32, "big") + utils.encode_message(tls_info)
        client_sign = HMAC(sha256(client_key), auth_msg)
        client_proof_calc = xor_bytes(client_key, client_sign)

        if client_proof != client_proof_calc:
            print("Proof verification failed.")
            send_message(conn, utils.encode_message({"status": "FAILED"}))
            return

        print("Proof verified. Sending challenge response...")

        salted_pw = database[username][2]
        server_key = HMAC(salted_pw, b"Client key")
        auth_msg = username.encode() + ch_1 + ch_2 + r + n.to_bytes(32, "big") + utils.encode_message(tls_info)
        server_sign = HMAC(server_key, auth_msg)

        send_message(conn, utils.encode_message({"status": "SUCCESS", "server_sign": server_sign}))

        print("Challenge response sent. Waiting for client confirmation.")

        if utils.decode_message(receive_message(conn))["status"] == "SUCCESS":
            print("Client confirmed. Connection established.")
        else:
            print("Client rejected the proof. Exiting.")
            return


def send_message(conn, message: bytes) -> None:
    conn.sendall(message)


def receive_message(conn) -> bytes:
    return conn.recv(4096)


def load_passwords(file):
    if not Path(file).exists():
        return
    with open(file, "r") as file:
        reader = csv.reader(file)
        for line in reader:
            if len(line) == 0:
                continue
            user, r, n, h_n = line
            n = int(n)
            r = bytes.fromhex(r)
            h_n = bytes.fromhex(h_n)

            database[user] = (r, n, h_n)


def save_passwords(file):
    with (open(file, "w", newline="") as file):
        writer = csv.writer(file)
        for user, (r, n, h_n) in database.items():
            writer.writerow([user, r.hex(), n, h_n.hex()])


if __name__ == "__main__":
    load_passwords("passwords.csv")
    start_ssl_server()
