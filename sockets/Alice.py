import hashlib
import socket
import sys
import threading
import time
import traceback

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jinja2.runtime import identity

import utils

# Configuration
MY_PORT = int(sys.argv[1])         # My listening port
TARGET_PORT = int(sys.argv[2])      # Peer's listening port
TARGET_HOST = '127.0.0.1'
MY_IDENTITY = sys.argv[3]
PEER_IDENTITY = sys.argv[4]

# Flag to track if the party is awaiting a response
awaiting_response = False

x = None
X = None

class ConnectionLostError(Exception):
    """Custom exception to indicate a lost connection."""
    pass


def listen_for_messages(conn, my_identity, peer_identity):
    """Continuously listen for incoming messages to act as a responder."""
    global awaiting_response, x
    while True:
        if not awaiting_response:
            try:
                # Receive a message from the peer
                data = conn.recv(1024)

                if not data:
                    raise ConnectionLostError("Connection lost: No data received.")

                decoded_data = data.decode('utf-8')
                print(f"{my_identity}: Receive a message: \"{decoded_data}\" ")


                salt = bytes([0] * hashlib.sha256().digest_size)
                # Convert the received data to a public key of the other party
                Y = decoded_data.encode()
                Y = serialization.load_pem_public_key(Y)
                Y_x = x.exchange(ec.ECDH(), Y)
                derived_key = utils.derive_key_from_shared_secret(Y_x, salt)

                print(f"{my_identity}: Derived key: {derived_key}")


                # Respond the message
                message = utils.to_bytes(X)
                conn.sendall(message)
                print(f"{my_identity}: Reply a message: \"{message}\" ")


            except (ConnectionResetError, BrokenPipeError, ConnectionLostError) as e:
                print(f"{my_identity}: Connection lost. Reconnecting...(Press any key to continue)")
                break
            except socket.timeout:
                continue  # No message received, continue listening

def initiate_key_exchange(conn, my_identity, peer_identity):
    """Handle initiating a key exchange when the user presses 'Y'."""
    global awaiting_response, x
    awaiting_response = True
    
    # Send a message to the peer
    conn.sendall(utils.to_bytes(X))
    print(f"{my_identity}: Sent g^x = X to {peer_identity}: \"{X}\" ")

    try:
        # Wait for response from the peer
        data = conn.recv(1024)
        if not data:
            raise ConnectionLostError("Connection lost.")
        
        decoded_data = data.decode('utf-8')
        print(f"{my_identity}: Receive a message from {peer_identity}: \"{decoded_data}\" ")

        salt = bytes([0] * hashlib.sha256().digest_size)
        # Convert the received data to a public key of the other party
        Y = decoded_data.encode()
        Y = serialization.load_pem_public_key(Y)
        Y_x = x.exchange(ec.ECDH(), Y)
        derived_key = utils.derive_key_from_shared_secret(Y_x, salt)

        print(f"{my_identity}: Derived key: {derived_key}")

    except (ConnectionResetError, BrokenPipeError, ConnectionLostError) as e:
        print(f"{my_identity}: Connection lost during initiation. Attempting to reconnect...")
        raise ConnectionLostError from e  # Propagate error to trigger reconnection
    except Exception as e:
        print(f"{my_identity}: Error - {e}, as initiator")
        traceback.print_exc()
    finally:
        awaiting_response = False  # Reset flag after completing the session

def run():
    global x, X

    print(f"Starting with name {MY_IDENTITY} ({MY_PORT}) to talk to {PEER_IDENTITY} ({TARGET_PORT})")

    my_identity = MY_IDENTITY
    peer_identity = PEER_IDENTITY

    x, X = utils.generate_ecdh_key_pair(ec.SECP256R1())

    while True:
        try:
            # Create a listening socket
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.bind((TARGET_HOST, int(MY_PORT)))
            listen_sock.listen()
            print(f"{my_identity}: Listening on port {MY_PORT}...")

            
            # Connect to the peer's listening port
            print(f"{my_identity}: Try connecting to {peer_identity}...")
            conn_to_peer = None
            while conn_to_peer is None:
                try:
                    conn_to_peer = socket.create_connection((TARGET_HOST, TARGET_PORT))
                except ConnectionRefusedError:
                    print(f"{my_identity}: Waiting for {peer_identity} to be online...")
                    time.sleep(2)
            
            # Wait for the connection from the peer to the party's listening port
            conn_from_peer, addr = listen_sock.accept()

            conn_to_peer.settimeout(2)
            conn_from_peer.settimeout(2)
            
            print(f"{my_identity}: Connected to {peer_identity}.")

            # conn_from_peer is for receiving messages
            listener_thread = threading.Thread(target=listen_for_messages, args=(conn_from_peer,my_identity, peer_identity), daemon=True)
            listener_thread.start()
            
            while listener_thread.is_alive():
                proceed = input(f"{my_identity}: Press 'Y' and Enter to initiate a session, or just wait to listen: \n").strip().upper()
                if proceed == "Y":
                    initiate_key_exchange(conn_to_peer, my_identity, peer_identity)

            print("Alice: Connection lost. Restarting connection...")
        except ConnectionLostError:
            print(f"{my_identity}: Attempting to reconnect...")
            time.sleep(2)  # Delay before re-entering the connection phase

if __name__ == "__main__":
    run()
