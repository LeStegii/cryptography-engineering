import os
from ssl import SSLSocket

from ecdsa import VerifyingKey

from project.util import crypto_utils
from project.util.message import *
from project.util.utils import debug


def handle_login(server, message: Message, client: SSLSocket, addr: tuple[str, int]):
    content = message.dict()
    if not server.is_registered(message.sender):
        debug(f"{message.sender}'s ({addr}) tried to login but isn't registered.")
        server.send(message.sender, {"status": NOT_REGISTERED}, LOGIN)
    else:
        debug(f"{message.sender} ({addr}) sent login request, checking attempts...")
        if server.check_too_many_attempts(message.sender):
            debug(f"{message.sender} ({addr}) has too many failed login attempts.")
            server.send(message.sender, {"status": ERROR, "error": "Too many failed login attempts."}, LOGIN)
            return
        debug("Checking password...")
        salted_password = content.get("salted_password")
        if salted_password == server.database.get(message.sender).get("salted_password"):
            debug(f"{message.sender}'s ({addr}) password is correct. User is now logged in.")
            server.send(message.sender, {"status": SUCCESS}, LOGIN)
            if "offline_messages" in server.database.get(message.sender):
                for offline_message in server.database.get(message.sender).get("offline_messages"):
                    server.send_bytes(offline_message.to_bytes(), message.sender)
                server.database.update(message.sender, {"offline_messages": []})
            server.database.update(message.sender, {"logged_in": True})
        else:
            debug(f"{message.sender}'s ({addr}) password is incorrect!")
            server.add_login_attempt(message.sender)
            server.send(message.sender, {"status": ERROR, "error": "Password incorrect."}, LOGIN)

def handle_register(server, message: Message, client: SSLSocket, addr: tuple[str, int]):
    content = message.dict()
    if server.is_registered(message.sender):
        debug(f"{message.sender} ({addr}) tried to register, but the user is already registered.")
        server.send(message.sender, {"status": ERROR, "error": "User is already registered."}, REGISTER)
        return

    password = content.get("password")
    key_bundle = content.get("keys")

    if not all([password, key_bundle]) or not isinstance(key_bundle, dict) or not isinstance(password, str):
        debug(f"{message.sender} ({addr}) sent invalid registration data.")
        server.send(message.sender, {"status": ERROR, "error": "Invalid registration data."}, REGISTER)

    if not all([key_bundle.get("IPK"), key_bundle.get("SPK"), key_bundle.get("OPKs"), key_bundle.get("sigma")]):
        debug(f"{message.sender} ({addr}) sent invalid key bundle.")
        server.send(message.sender, {"status": ERROR, "error": "Invalid key bundle."}, REGISTER)

    if not all([isinstance(key_bundle.get("IPK"), VerifyingKey), isinstance(key_bundle.get("SPK"), VerifyingKey), isinstance(key_bundle.get("sigma"), bytes)]):
        debug(f"{message.sender} ({addr}) sent invalid key bundle.")
        server.send(message.sender, {"status": ERROR, "error": "Invalid key bundle."}, REGISTER)
        return

    if not all([isinstance(opk, VerifyingKey) for opk in key_bundle.get("OPKs")]):
        debug(f"{message.sender} ({addr}) sent invalid key bundle.")
        server.send(message.sender, {"status": ERROR, "error": "Invalid key bundle."}, REGISTER)
        return

    user_known = server.database.has(message.sender)
    salt_set = user_known and server.database.get(message.sender).get("salt")
    pepper_set = user_known and server.peppers.get(message.sender)

    debug(f"{message.sender} ({addr}) is trying to register.")

    salt = server.get_or_gen_salt(message.sender)
    if not salt_set:
        debug(f"Creating salt for {message.sender} ({addr}).")
        server.database.update(message.sender, {"salt": salt})

    if not pepper_set:
        debug(f"Creating pepper for {message.sender} ({addr}).")
        pepper = os.urandom(32)
        server.peppers.insert(message.sender, pepper)

    debug(f"Saving password for {message.sender} ({addr}). Sending salt to client.")

    salted_password = crypto_utils.salt_password(password, server.database.get(message.sender).get("salt"), server.peppers.get(message.sender))
    server.database.update(message.sender, {"salted_password": salted_password, "keys": key_bundle, "registered": True})
    server.send(message.sender, {"status": SUCCESS, "salt": salt, "pepper": server.peppers.get(message.sender)}, REGISTER)

def handle_request_salt(server, message: Message, client: SSLSocket, addr: tuple[str, int]):
    debug(f"{addr} sent REQUEST_SALT as {message.sender}. Sending salt.")
    server.send(message.sender, {"salt": server.get_or_gen_salt(message.sender)}, ANSWER_SALT)