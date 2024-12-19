import csv
import os
import ssl
import socket
from pathlib import Path
from threading import Timer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from homework2.lecture7.auth import client

key = None

# username -> (salt, enc(hashed_password), iv, tag)
salted_hashes = {

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
                    iv, encrypted_password, tag = encode_password(username, hashed_password)
                    salted_hashes[username] = (salt, encrypted_password, iv, tag)
                    send_message(conn, b"AccountCreated")
                    save_passwords("passwords.csv")

            elif data.startswith(b"LoginRequest="):
                username = data.decode().split("=")[1]

                if username in currently_blocked and currently_blocked[username] >= 3:
                    print(f"User {username} is currently blocked.")
                    send_message(conn, b"UserBlocked")
                    continue

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

                iv = salted_hashes[username][2]
                tag = salted_hashes[username][3]
                stored_encrypted_password = salted_hashes[username][1]
                decrypted_password = decode_password(username, stored_encrypted_password, iv, tag)

                if hashed_password == decrypted_password:
                    send_message(conn, b"LoginSuccess")
                    print(f"User {username} logged in successfully.")
                    unblock_user(username)
                else:
                    send_message(conn, b"LoginFailed")
                    print(f"User {username} login failed.")
                    if username in currently_blocked:
                        currently_blocked[username] += 1
                    else:
                        currently_blocked[username] = 1

                    if currently_blocked[username] >= 3:
                        print(f"User {username} is now blocked.")
                        Timer(180, unblock_user, args=(username,)).start()

def unblock_user(username):
    if username in currently_blocked:
        currently_blocked.pop(username)
        print(f"Unblocking user {username}.")

def send_message(conn, message: bytes) -> None:
    conn.sendall(message)


def receive_message(conn) -> bytes:
    return conn.recv(4096)


def decode_password(user, encrypted_password, iv, tag):
    return aes_gcm_decrypt(key, iv, encrypted_password, user.encode(), tag)


def encode_password(user, password):
    iv, encrypted_password, tag = aes_gcm_encrypt(key, password, user.encode())
    return iv, encrypted_password, tag


def load_passwords(file):
    if not Path(file).exists():
        return
    with open(file, "r") as file:
        reader = csv.reader(file)
        for line in reader:
            if len(line) == 0:
                continue
            user, salt, encrypted_password, iv, tag = line
            salt = bytes.fromhex(salt)
            encrypted_password = bytes.fromhex(encrypted_password)
            iv = bytes.fromhex(iv)
            tag = bytes.fromhex(tag)

            salted_hashes[user] = (salt, encrypted_password, iv, tag)


def save_passwords(file):
    with (open(file, "w", newline="") as file):
        writer = csv.writer(file)
        for user, (salt, encrypted_password, iv, tag) in salted_hashes.items():
            writer.writerow([user, salt.hex(), encrypted_password.hex(), iv.hex(), tag.hex()])


def aes_gcm_encrypt(key, plaintext, associated_data):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag


def aes_gcm_decrypt(key, iv, ciphertext, associated_data, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decryptor.authenticate_additional_data(associated_data)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


def generate_or_load_key() -> bytes:
    if not Path("peppering.txt").exists():
        with open("peppering.txt", "wb") as file:
            keygen = os.urandom(32)
            file.write(keygen.hex().encode())
    else:
        with open("peppering.txt", "rb") as file:
            keygen = bytes.fromhex(file.readline().decode())

    return keygen


if __name__ == "__main__":
    key = generate_or_load_key()
    load_passwords("passwords.csv")
    start_ssl_server()
