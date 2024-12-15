import socket
import ssl
import threading
import traceback
from typing import Optional


class Client:
    def __init__(self, host="localhost", port=25566):
        self.host: str = host
        self.port: int = port
        self.client_socket: Optional[ssl.SSLSocket] = None

    def connect(self):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Wrap with SSL
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.load_verify_locations("server.pem")
            self.client_socket = context.wrap_socket(raw_socket, server_hostname=self.host)

            self.client_socket.connect((self.host, self.port))
            print(f"Connected to server {self.host}:{self.port}.")
        except Exception as e:
            traceback.print_exc()
            print("Failed to connect to the server.")
            raise e

    def send(self, message):
        try:
            self.client_socket.send(message.encode())
        except Exception:
            traceback.print_exc()
            print("Failed to send the message.")

    def receive_message(self):
        try:
            while True:
                message = self.client_socket.recv(1024)
                if message:
                    print(f"Received: {message.decode()}")
                else:
                    print("Connection closed by server.")
                    break
        except ConnectionResetError:
            traceback.print_exc()
            print("Connection was reset by the server.")
        except Exception as e:
            traceback.print_exc()
            print("Error receiving message.")

    def send_messages(self):
        """Handles user input and sends messages to the server."""
        try:
            while True:
                msg = input("Enter a message: ")
                if msg.lower() == "exit":
                    print("Closing connection.")
                    self.client_socket.close()
                    break
                self.send(msg)
        except Exception as e:
            traceback.print_exc()
            print("Error sending messages.")

    def start(self):
        self.connect()

        username = input("Enter your username: ")
        password = input("Enter your password: ")

        print("Generating keys...")

        receive_thread = threading.Thread(target=self.receive_message, daemon=True)
        receive_thread.start()

        self.send_messages()


if __name__ == "__main__":
    import sys

    HOST = "localhost" if len(sys.argv) < 3 else sys.argv[2]
    PORT = 25566 if len(sys.argv) < 4 else int(sys.argv[3])

    client = Client(HOST, PORT)
    client.start()
