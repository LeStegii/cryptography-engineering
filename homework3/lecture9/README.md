# How to use?

1. Use `openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.key` to create the keys and certificates required for the SSL socket to work.
2. Set `Common Name (e.g. server FQDN or YOUR name) []:` to localhost.
3. Start the server using `python3 server.py`.
4. Start two or more clients using `python3 client.py`.
5. Enter your username in the client terminal and enter your password (if you are logging in for the first time).
6. Send your password.

# What is the RTT of OPAQUE?

Answer: 3 RTT
Reason: First, one RTT is needed for the OPRF, one for the AKE and one for the confirmation. The registration only needs have a RTT since the server doesn't have to answer.
