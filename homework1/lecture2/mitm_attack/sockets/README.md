1. Start the server using `python3 mitm_server.py`.
2. Start Alice using `python3 mitm_user.py Alice`.
3. Start Bob using `python3 mitm_user.py Bob`.

Alice and Bob send their private keys to the server.
The server then calculates two new public keys and sends them to Alice and Bob.
Bob then sends a message to the server (thinking it is Alice) and the server encrypts the message using the key generated for Bob, encrypts it again using the key generated for Alice, and sends it to Alice.
Alice can then decrypt the message using her key and sees the message Bob sent.