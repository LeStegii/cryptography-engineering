# How to use?

1. Use `openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.key` to create the keys and certificates required for the SSL socket to work.
2. Set `Common Name (e.g. server FQDN or YOUR name) []:` to localhost.
3. Start the server using `python3 server.py`.
4. Start two or more clients using `python3 client.py`.
5. Enter your username in the client terminal.
6. Send your password.