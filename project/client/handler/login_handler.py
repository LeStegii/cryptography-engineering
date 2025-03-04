import threading

from project.util import crypto_utils
from project.util.message import Message, ERROR, NOT_REGISTERED, LOGIN, REGISTERED, REQUEST_SALT, REGISTER, SUCCESS
from project.util.utils import debug


def login(client, password: str) -> bool:
    salt = client.database.get("salt")
    if not salt:
        debug("Salt not found in database. This should not happen. Please request it again.")
        return False
    salted_password = crypto_utils.salt_password(password, client.database.get("salt"), client.database.get("pepper"))
    client.send("server", {"salted_password": salted_password}, LOGIN)
    return True


def handle_status(client, message: Message) -> bool:
    content = message.dict()
    if content.get("status") == ERROR:
        debug(f"Received error from client: {content.get('error')}")
        return False
    elif content.get("status") == NOT_REGISTERED:
        debug("User not registered.")
        password = input("Enter your new password: ")
        debug("Computing keys...")
        keys = client.load_or_gen_keys()
        key_bundle = {
            "IPK": keys["IPK"],
            "SPK": keys["SPK"],
            "OPKs": keys["OPKs"],
            "sigma": keys["sigma"]
        }
        debug("Sending registration request to server...")
        client.send("server", {"password": password, "keys": key_bundle}, REGISTER)
    elif content.get("status") == REGISTERED:
        debug("User registered. Requesting salt from client...")
        client.send("server", {}, REQUEST_SALT)
    else:
        debug(f"Received unknown status from client: {content.get('status')}")
        return False
    return True


def handle_register(client, message: Message) -> bool:
    if message.dict().get("status") == SUCCESS:
        salt = message.dict().get("salt")
        pepper = message.dict().get("pepper")
        if not all(value and isinstance(value, bytes) for value in [salt, pepper]):
            debug("Received invalid salt/pepper from server.")
            return False
        client.database.insert("salt", salt)
        client.database.insert("pepper", pepper)
        debug(f"Received salt and pepper from server.")
        debug("User registered successfully. You can now login.")
        password = input("Enter your password: ")
        if not login(client, password):
            debug("Error logging in.")
            return False
    elif message.dict().get("status") == ERROR:
        debug("Error registering user: " + message.dict().get("error"))
        return False
    return True


def handle_login(client, message: Message) -> bool:
    if message.dict().get("status") == SUCCESS:
        debug("User logged in successfully.")
        # Execute the send_messages function in a new thread
        client.send_thread = threading.Thread(target=client.send_messages, daemon=True)
        client.send_thread.start()
    elif message.dict().get("status") == ERROR:
        debug(f"Error logging in: {message.dict().get('error')}")
        return False
    return True


def handle_answer_salt(client, message: Message) -> bool:
    salt = message.dict().get("salt")
    if not salt or not isinstance(salt, bytes):
        debug("Received invalid salt from server.")
        return False
    client.database.insert("salt", salt)
    password = input("Received salt for login. Please enter your password: ")
    if not login(client, password):
        debug("Error logging in.")
        return False
    return True
