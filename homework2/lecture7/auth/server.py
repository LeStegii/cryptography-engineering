import csv
import os
import ssl
import socket
from pathlib import Path

from homework2.lecture7.auth import client

salted_hashes = {

}

def start_ssl_server(host="localhost", port=12345, certfile="server.pem", keyfile="server.key"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"Server listening on {host}:{port}")
    with context.wrap_socket(server_socket, server_side=True) as ssock:
        conn, addr = ssock.accept()
        print(f"Connection established with {addr}")

        while True:
            data = receive_message(conn)
            if data == b"exit":
                print("Client disconnected.")
                break
            print(f"Received: {data}")
            if data.startswith(b"CreateAccount="):
                split = data.decode().split("=")
                if len(split) != 2 or split[1].count(",") != 1:
                    print("Received invalid format.")
                    continue
                username, password = split[1].split(",")
                if len(username) < 1 or len(password) < 1:
                    print("Username and password cannot be empty.")
                    continue
                if username in salted_hashes:
                    send_message(conn, b"AccountExists")
                else:
                    salt = os.urandom(32)
                    hashed_password = client.hash_password(password, salt)
                    salted_hashes[username] = (salt, hashed_password)
                    send_message(conn, b"AccountCreated")
                    save_passwords("passwords.csv")

            elif data.startswith(b"LoginRequest="):
                username = data.decode().split("=")[1]
                if len(username) < 1:
                    print("Received empty username...")
                    continue
                if username in salted_hashes:
                    print("Sending salt.")
                    send_message(conn, salted_hashes[username][0])
                else:
                    print("Sending user not found to client.")
                    send_message(conn, b"UserNotFound")
                    continue

                hashed_password = receive_message(conn)
                print(f"Received hashed password {hashed_password}.")

                if hashed_password == salted_hashes[username][1]:
                    send_message(conn, b"LoginSuccess")
                else:
                    send_message(conn, b"LoginFailed")

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
            if len(line) != 3:
                continue
            user, salt, hashed_password = line
            salted_hashes[user] = (bytes.fromhex(salt), bytes.fromhex(hashed_password))

def save_passwords(file):
    with (open(file, "w", newline="") as file):
        writer = csv.writer(file)
        for user, (salt, hashed_password) in salted_hashes.items():
            writer.writerow([user, salt.hex(), hashed_password.hex()])

if __name__ == "__main__":
    load_passwords("passwords.csv")
    start_ssl_server()