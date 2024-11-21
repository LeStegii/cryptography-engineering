# Server

This is a simple server for messaging using sockets.
First, the user has to send their identity, after that, they can send messages to the server.
The server will broadcast the message to all the users connected to it.
If the message contains a request prefix as well as the identifier "public_key", all users receiving the message will send their public key to the server starting a key exchange.

## Usage

To run the server, execute the following command:
Ports, IPs and other configurations can be changed using runtime parameters.

```bash
python3 connection_server.py 
python3 sender.py Alice
python3 sender.py Bob
```

Send `request_pk` to initiate a key exchange from your side.