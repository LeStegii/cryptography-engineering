import json
import socket
import sys
import time

import requests
from cryptography.hazmat.primitives._serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa import VerifyingKey

import utils
from homework1.lecture2.bonus import pki_server

port = 12345
host = "127.0.0.1"

def main():

    if len(sys.argv) < 2:
        print("Usage: python user.py <1/2>")
        return

    if sys.argv[1] == "1":
        user = "Alice"
    elif sys.argv[1] == "2":
        user = "Bob"
    else:
        print("Usage: python user.py <1/2>")
        return

    x, X = utils.generate_ecdh_key_pair(ec.SECP521R1())
    print("My public key: " + X.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex())

    # HTTP request to get X signed by the server

    url = f"http://127.0.0.1:{pki_server.PORT}"
    print(f"Requesting signature from {url}...")
    response = requests.post(url, data=json.dumps({"pk_u": X.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo).hex()}), headers={'Content-Type': 'application/json'})


    if response.status_code == 200:
        pk_s = VerifyingKey.from_pem(bytes.fromhex(response.json()["pk_s"]).decode("utf-8"))
        cert = bytes.fromhex(response.json()["cert"])
        print("Received signed key from server")
    else:
        print("Error while signing key: " + str(response.status_code))
        return

    # Connect to the other socket and exchange keys and wait until other socket is online

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if user == "Alice":
        sock.bind((host, port))
        sock.listen(1)
        print("Waiting for Bob to connect...")
        conn, addr = sock.accept()
        print(f"Connected by {addr}")

        print("Sending public key and certificate to Bob...")
        print("Certificate: " + cert.hex())
        print("My Public key: " + X.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex())

        conn.sendall(X.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        conn.sendall(cert)

        pk_received = conn.recv(4096)
        cert_received = conn.recv(4096)

        print("Received public key and certificate from Bob...")
        print("Certificate: " + cert_received.hex())
        print("Bob Public key: " + pk_received.hex())

        try:
            if not pk_s.verify(cert_received, pk_received):
                print("Error: Signature verification failed")
                return
            else:
                print("Signature verified")
        except:
            print("Error: Signature verification failed")
            return

    elif user == "Bob":
        print("Connecting to Alice...")

        while True:
            try:
                sock.connect((host, port))
                break
            except ConnectionRefusedError:
                print("Connection refused, retrying...")
                time.sleep(1)

        pk_received = sock.recv(4096)
        cert_received = sock.recv(4096)

        print("Received public key and certificate from Alice...")
        print("Certificate: " + cert_received.hex())
        print("Alice Public key: " + pk_received.hex())

        try:
            if not pk_s.verify(cert_received, pk_received):
                print("Error: Signature verification failed")
                return
            else:
                print("Signature verified")
        except:
            print("Error: Signature verification failed")
            return

        print("Sending public key and certificate to Alice...")
        print("Certificate: " + cert.hex())
        print("My Public key: " + X.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex())

        sock.sendall(X.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        sock.sendall(cert)

    sock.close()

if __name__ == "__main__":
    main()

