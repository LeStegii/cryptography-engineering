# Cryptography Engineering

This repository contains code for the course "Cryptography Engineering" at the University of Kassel in the winter semester 2024/2025.

## Lecture 1

### Tasks
1. Find some useful cryptographic libraries (Python: PyNaCl, ecdsa, cryptography, PyCryptodomem, etc.), Google (Bing/ChatGPT/...) them and figure out how to install them!
2. Given the example code of DHKE, implement the hashed ElGamal encryption

This has been implemented in [`crypto/hashed_elgamal.py`](crypto/hashed_elgamal.py).

### Homework

- Consider implementing DHKE to enable two programs on your PC to perform a key exchange (using sockets, etc.)
   1. Program Alice <-- (connection) --> Program Bob
   2. Program Alice -- g^x --> Program Bob
   3. Program Alice <-- g^y -- Program Bob

This has been implemented in [`homework1/lecture1/sockets/socket_user.py`](homework1/lecture1/sockets/socket_user.py).
Use the following commands to run the program:
```bash
python3 socket_user.py Alice 12345 54321
python3 socket_user.py Bob 54321 12345
```

- Add a trusted server to help the key exchange procedure (using sockets, etc.)
   1. Program Alice <-- (connection) --> Server <-- (connection) --> Program Bob
   2. Program Alice -- g^x --> Server -- g^x --> Program Bob
   3. Program Alice <-- g^y -- Server <-- g^y -- Program Bob

This has been added to [`homework1/lecture1/server/`](homework1/lecture1/server).
For more information see the [README](homework1/lecture1/server/README.md).

### Lecture 2

#### Tasks

1. Export a certificate from a website, and then use the example code ReadCert.py to read the certificate.
2. Find and export a pre-installed certificate on your laptop or PC (via browser), and use the example code to read the certificate.

This can be done using [`crypto/ReadCert.py`](crypto/ReadCert.py).

#### Homework

- Implement a man-in-the-middle attack (in one program) on DHKE.

This has been implemented in [`homework1/lecture2/mitm_attack/dhke_mitm.py`](homework1/lecture2/mitm_attack/dhke_mitm.py).

- Use the example code ‘ECDSA.py’ to demonstrate the nonce-reuse attack on ECDSA (i.e., recover the secret key given two valid signatures using the same randomness)

This has been added to [`homework1/lecture2/ECDSA.py`](homework1/lecture2/ECDSA.py).

- Bonus: Implement a man-in-the-middle attack on DHKE using sockets.

TODO 

- Bonus: Use a trusted server and signatures to securely exchange public keys (using sockets): See next slide.
   1. Alice and Bob each have the server’s public key pre-installed, which they will use to verify the server's digital signatures.
   2. To initiate the key exchange, Alice first requests the server to generate a digital signature for her public key.
   3. After receiving the signed public key from the server, Alice sends her public key and the server’s signature to Bob.
   4. Bob, upon receiving (pk_alice, signature of pk_alice), verifies the signature with the server’s public key. If the signature is valid, Bob accepts pk_alice. Next, Bob requests a signature for his own public key from the server, following a similar process as Alice.
   5. Finally, Bob sends (pk_bob, signature of pk_bob) to Alice. Alice verifies the signature using the server’s public key and, if valid, accepts pk_bob.

TODO

### Lecture 3

#### Tasks
1. Run the example code “HKDF.py”. Play with it and learn how to derive keys from a secret.
![Task 1](resources/lecture3-task1.png)

#### Homework
- Implement the tweaked TLS handshake protocol (in the Client-Server setting using sockets)
  - Use the simplified key schedule algorithm:
  - ![Homework](resources/lecture3-homework1.png)
  - ![Homework](resources/lecture3-homework2.png)
  - ![Homework](resources/lecture3-homework3.png)

This has been implemented in [`homework2/lecture3/tls`](homework2/lecture3/tls).

- Bonus: Implement the same protocol, but this time use SHA3-512 as the hash function (for HKDF, HMAC, and the key schedule) and P-521 as the elliptic curve for key exchange. This should allow you to derive a key with 512 bits (64 bytes).