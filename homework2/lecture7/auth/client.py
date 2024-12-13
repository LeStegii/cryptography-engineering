import ssl
import socket
import hashlib


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)


def start_ssl_client(host="localhost", port=12345, cafile="server.pem"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile)

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:


            print(f"Connected to {host}:{port}")
            print("Type 'help' or '?' for help.")

            while True:
                message = input("Enter message: ")

                if message == "exit":
                    print("Exiting...")
                    break

                if message == "?" or message == "help":
                    print("CreateAccount=USER,PASSWORD:\t\tCreate an account, will fail if USER exists")
                    print("LoginRequest=USER\t\t\t\tLogin as USER, will prompt for a password if USER exists")
                    continue

                if message.startswith("CreateAccount="):
                    split = message.split("=")
                    if len(split) != 2 or split[1].count(",") != 1:
                        print("Please use CreateAccount=USER,PASSWORD")
                        continue
                    username, password = split[1].split(",")
                    if len(username) < 1 or len(password) < 1:
                        print("Username and password cannot be empty.")
                        continue
                    print(f"Creating account: {username}")
                    send_message(ssock, message.encode())
                    response = receive_message(ssock)
                    print(f"Received response: {response}")
                    if response == b"AccountCreated":
                        print("Account created.")
                    elif response == b"AccountExists":
                        print("Account creation failed.")

                elif message.startswith("LoginRequest="):
                    username = message.split("=")[1]
                    if len(username) < 1:
                        print("Username cannot be empty!")
                    print(f"Sending login request for account: {username}")
                    send_message(ssock, message.encode())
                    response = receive_message(ssock)
                    print(f"Received response: {response}")
                    if response == b"UserNotFound":
                        print("User not found.")
                    else:
                        print("Receiving salt...")
                        salt = response
                        print(f"Received salt: {salt}")

                        password = input("Enter password: ")

                        print("Hashing password and salt...")
                        hashed_password = hash_password(password, salt)
                        print(f"Hashed password: {hashed_password}")

                        print("Sending hashed password...")
                        send_message(ssock, hashed_password)

                        print("Receiving response...")
                        response = receive_message(ssock)
                        print(f"Received response: {response}")
                        if response == b"LoginSuccess":
                            print("Login successful.")
                        else:
                            print("Login failed.")

def send_message(conn, message: bytes) -> None:
    conn.sendall(message)

def receive_message(conn) -> bytes:
    return conn.recv(4096)

if __name__ == "__main__":
    start_ssl_client()
