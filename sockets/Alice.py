import socket
import threading
import time

# Configuration
MY_PORT = 65432         # My listening port
TARGET_PORT = 65433      # Peer's listening port
TARGET_HOST = '127.0.0.1'

# Flag to track if the party is awaiting a response
awaiting_response = False

class ConnectionLostError(Exception):
    """Custom exception to indicate a lost connection."""
    pass


def listen_for_messages(conn, my_identity, peer_identity):
    """Continuously listen for incoming messages to act as a responder."""
    global awaiting_response
    while True:
        if not awaiting_response:
            try:
                # Receive a message from the peer
                data = conn.recv(1024)

                if not data:
                    raise ConnectionLostError("Connection lost: No data received.")
                
                decoded_data = data.decode('utf-8')
                print(f"{my_identity}: Receive a message: \"{decoded_data}\" ")


                # Respond the message
                message = f"Hey {peer_identity}! I received your message."
                conn.sendall(message.encode('utf-8'))
                print(f"{my_identity}: Reply a message: \"{message}\" ")


            except (ConnectionResetError, BrokenPipeError, ConnectionLostError) as e:
                print(f"{my_identity}: Connection lost. Reconnecting...(Press any key to continue)")
                break
            except socket.timeout:
                continue  # No message received, continue listening

def initiate_key_exchange(conn, my_identity, peer_identity):
    """Handle initiating a key exchange when the user presses 'Y'."""
    global awaiting_response
    awaiting_response = True
    
    # Send a message to the peer
    message = f"Hey {peer_identity}, this is {my_identity}"
    conn.sendall(message.encode('utf-8'))
    print(f"{my_identity}: Send a message to {peer_identity}: \"{message}\" ")

    try:
        # Wait for response from the peer
        data = conn.recv(1024)
        if not data:
            raise ConnectionLostError("Connection lost.")
        
        decoded_data = data.decode()
        print(f"{my_identity}: Receive a message from {peer_identity}: \"{decoded_data}\" ")

    except (ConnectionResetError, BrokenPipeError, ConnectionLostError) as e:
        print(f"{my_identity}: Connection lost during initiation. Attempting to reconnect...")
        raise ConnectionLostError from e  # Propagate error to trigger reconnection
    except Exception as e:
        print(f"{my_identity}: Error - {e}, as initiator")
    finally:
        awaiting_response = False  # Reset flag after completing the session

def alice():

    my_identity = "Alice"
    peer_identity = "Bob"
    while True:
        try:
            # Create a listening socket
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.bind((TARGET_HOST, MY_PORT))
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
    alice()
