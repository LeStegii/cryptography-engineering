1. Use `openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.key` to create the keys and certificates required for the SSL socket to work.
2. Set `Common Name (e.g. server FQDN or YOUR name) []:` to localhost.
3. Start the server using `python3 server.py`.
4. Start the client using `python3 client.py`

Using `CreateAccount=USER,PASSWORD` the user can create an account on the server.
The server will then reply with either `AccountCreated` or `UserExists`.

Using `LoginRequest=USER` the user can try to login.
The server will reply with the salt and prompts the client for the password.
The client computes the salted hash of the password and then sends it to the server.
The server will then reply with either `LoginSuccess` or `LoginFailed`.
If the specified user doesn't exist yet, the server will send `UserNotFound`.