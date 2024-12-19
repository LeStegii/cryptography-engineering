# How to setup?

1. Use `openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.key` to create the keys and certificates required for the SSL socket to work.
2. Set `Common Name (e.g. server FQDN or YOUR name) []:` to localhost.
3. Start the server using `python3 server.py`.
4. Start the client using `python3 client.py`

# How to use?

Using `CreateAccount=USER,PASSWORD` the user can create an account on the server.
The server will then reply with either `AccountCreated` or `UserExists`.

Using `LoginRequest=USER` the user can try to login.
The server will reply with the salt and prompts the client for the password.
The client computes the salted hash of the password and then sends it to the server.
The server will then reply with either `LoginSuccess` or `LoginFailed`.
If the specified user doesn't exist yet, the server will send `UserNotFound`.

# How does it work?

The whole communication is encrypted using TLS, meaning that the data is encrypted before being sent over the network.
This prevents attackers from reading the data being sent over the network.

The server stores the name of an account together with the salted hash of the password and the corresponding salt.
To prevent attackers from doing an offline dictionary attack in case of a database leak, the server encrypts the data with a secret key.
This secret key is stored in the server side in a different database and is never sent over the network.

When a user tries to login by sending the username, the server will reply with the salt and prompt the client for the password.
The client will then compute the salted hash of the password and send it to the server.
The server decrypts its database and compares the computed hash with the stored hash.
If they match, the server will send `LoginSuccess`, otherwise `LoginFailed`.

## How are online dictionary attacks prevented?

The server will lock the account for 3 minutes after 3 failed login attempts.
This prevents attackers from trying to guess the password by trying all possible passwords in a short amount of time.

## How are offline dictionary attacks prevented?

Since the server encrypts the data with a secret key, an attacker cannot perform an offline dictionary attack even if he somehow gets access to the database.
The attacker would need the secret key to decrypt the data, which is stored server side and never sent over the network.

The attack would only work again if the attacker also gets access to the key.