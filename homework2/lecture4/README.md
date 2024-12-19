# How to use?

1. Use `openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.key` to create the keys and certificates required for the SSL socket to work.
2. Set `Common Name (e.g. server FQDN or YOUR name) []:` to localhost.
3. Start the server using `python3 x3dh_server.py`.
4. Start two or more clients using `python3 x3dh_client.py`.
5. Type your name in the clients and press enter.
6. Type `x3dh USER` to start the X3DH protocol with the user `USER`.
7. The clients will exchange messages.
8. The clients will print the generated keys.