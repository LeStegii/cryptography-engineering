import hashlib
import socket
import sys
import threading
import traceback

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import utils
from constants import REQUEST_PREFIX, PK, MESSAGE_PREFIX, ANSWER_PREFIX, IDENTITY_PREFIX

HOST = '127.0.0.1' if len(sys.argv) < 3 else sys.argv[2]
PORT = 25566 if len(sys.argv) < 4 else int(sys.argv[3])
IDENTITY = 'User' if len(sys.argv) < 2 else sys.argv[1]

client_private_key = ""
client_public_key = ""


def receive_message(client_socket):
    while True:
        try:
            message = client_socket.recv(1024)
            if message:
                msg = message.decode('utf-8')
                user = msg.split(":")[0]
                if REQUEST_PREFIX + PK in msg:
                    print(f"{user} requested public key.")
                    send(client_socket, utils.to_bytes(client_public_key).decode('utf-8'), msg_type=ANSWER_PREFIX)
                    continue
                if MESSAGE_PREFIX in msg:
                    print(msg.replace(MESSAGE_PREFIX, ""))
                    continue
                if ANSWER_PREFIX in msg:
                    print(f"Received public key from {user}.")
                    salt = bytes([0] * hashlib.sha256().digest_size)
                    other_pk = serialization.load_pem_public_key(msg.replace(ANSWER_PREFIX, '').split(":")[1].encode('utf-8'))
                    shared_secret = client_private_key.exchange(ec.ECDH(), other_pk)
                    shared_key = utils.derive_key_from_shared_secret(shared_secret, salt)
                    print(f"Shared key with {user}: {shared_key}")
                    continue
            else:
                break
        except ConnectionResetError as e:
            # Print stacktrace
            traceback.print_exc()
            print("Couldn't receive message from the server!")
            break


def send_messages(client_socket):
    while True:
        msg = input()
        if msg == "exit":
            client_socket.close()
            break
        if msg == "request_pk":
            send(client_socket, PK, msg_type=REQUEST_PREFIX)
            continue

        send(client_socket, msg)


def send(client_socket, message, msg_type=MESSAGE_PREFIX):
    message = message.replace("$", "")
    client_socket.send((msg_type + message).encode('utf-8'))

def start_client(host, port):
    global client_private_key, client_public_key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"Connected to server {host}:{port}.")

    send(client_socket, IDENTITY, msg_type=IDENTITY_PREFIX)
    print(f"Sent identity {IDENTITY} to server.")

    print("Generating keys...")
    client_private_key, client_public_key = utils.generate_ecdh_key_pair(ec.SECP256R1())
    print(f"Generated keys: {client_private_key}, {client_public_key}")

    print("You can now start chatting with the server.")

    receive_thread = threading.Thread(target=receive_message, args=(client_socket,))
    receive_thread.start()

    send_messages(client_socket)


if __name__ == "__main__":
    start_client(HOST, PORT)
