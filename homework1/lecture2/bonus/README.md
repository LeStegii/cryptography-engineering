## Usage

The program has been implemented using a HTTP server for the PKI server and two clients to simulate the sender and receiver.
To run the program, execute the following commands:

```bash
python3 pki_server.py 
python3 sender.py 1
python3 sender.py 2
```

## Expected Output

### Server

```bash
Server public key: sss
Starting server on port 127.0.0.1:25566...
127.0.0.1 - - [16/Feb/2025 11:00:53] "POST / HTTP/1.1" 200 -
Received public key from user: aaa
127.0.0.1 - - [16/Feb/2025 11:00:54] "POST / HTTP/1.1" 200 -
Received public key from user: bbb
```

### Sender 1

```bash
My public key: aaa
Requesting signature from http://127.0.0.1:25566...
Received signed key from server
Waiting for Bob to connect...
Connected by ('127.0.0.1', 55823)
Sending public key and certificate to Bob...
Certificate: ccc_a
My Public key: aaa
Received public key and certificate from Bob...
Certificate: ccc_b
Bob Public key: bbb
Signature verified
```

### Sender 2

```bash
My public key: bbb
Requesting signature from http://127.0.0.1:25566...
Received signed key from server
Connecting to Alice...
Received public key and certificate from Alice...
Certificate: ccc_a
Alice Public key: aaa
Signature verified
Sending public key and certificate to Alice...
Certificate: ccc_b
My Public key: bbb
```