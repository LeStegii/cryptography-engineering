import socket
import sys
import threading

from server.constants import IDENTITY_PREFIX

HOST = '127.0.0.1' if len(sys.argv) < 2 else sys.argv[1]
PORT = 25566 if len(sys.argv) < 3 else int(sys.argv[2])

clients = {}

def handle_client(connection, address):
    print(f"New connection from {address}")
    try:
        while True:
            message = connection.recv(1024)
            if connection not in clients:
                msg = message.decode('utf-8')
                if IDENTITY_PREFIX not in msg:
                    print(f"Client {address} didn't send their identity as their first message.")
                else:
                    clients[connection] = msg.replace(IDENTITY_PREFIX, "")
            else:
                if not message:
                    print(f"Client {clients[connection]} ({address}) disconnected!")
                    break
                broadcast(message, connection)
    except ConnectionResetError:
        print(f"Connection with {clients[connection]} (address) was lost.")
    finally:
        clients[connection] = None
        connection.close()

def broadcast(message, sender):
    for client in clients:
        if client != sender:
            try:
                client.send(f"{clients[sender]}:".encode('utf-8') + message)
            except:
                clients[client] = None
                try:
                    client.close()
                except:
                    pass


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Started server on {HOST}:{PORT}")

    while True:
        # Wait for connections and start a thread for each one
        connection, address = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(connection, address))
        thread.start()


if __name__ == "__main__":
    start_server()