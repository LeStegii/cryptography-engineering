import traceback
from ssl import SSLSocket

from ecdsa import VerifyingKey

from project.util.message import *
from project.util.serializer import serializer
from project.util.utils import check_username, debug


def handle_x3dh_bundle_request(server, message: Message, client: SSLSocket, addr: tuple[str, int]):
    """Called when a client requests a key bundle."""
    target = message.dict().get("target")
    if not target or not check_username(target):
        debug(f"{message.sender} ({addr}) sent a key request without a valid target.")
        server.send(message.sender, {"status": ERROR, "error": "No valid target specified."}, X3DH_BUNDLE_REQUEST)
        return

    if not server.is_registered(target):
        debug(f"{message.sender} ({addr}) sent a key request to an unregistered user ({target}).")
        server.send(message.sender, {"status": ERROR, "error": f"{target} is not registered."}, X3DH_BUNDLE_REQUEST)
        return

    keys = server.database.get(target).get("keys")
    if not keys:
        debug(f"{message.sender} ({addr}) sent a key request to {target}, but the user has no keys (something went wrong here!).")
        server.send(message.sender, {"status": ERROR, "error": f"Key request for {target} failed."}, X3DH_BUNDLE_REQUEST)
        return

    debug(f"{message.sender} ({addr}) sent a key request for {target}. Sending keys.")

    if len(keys.get("OPKs")) == 0:
        debug(f"{target} has no one-time prekeys left.")
        if server.is_logged_in(target):
            debug(f"{target} is online. Requesting keys.")
            server.send(target, {}, X3DH_REQUEST_KEYS)
            server.send(message.sender, {"status": ERROR, "error": f"{target} doesn't have keys left. Try again."}, X3DH_BUNDLE_REQUEST)
        else:
            debug(f"{target} is offline. Saving message for later and notifying sender.")
            server.add_offline_message(target, Message(serializer.encode_message({}), "server", target, X3DH_REQUEST_KEYS))
            server.send(message.sender, {"status": ERROR, "error": f"{target} doesn't have keys left and is offline."}, X3DH_BUNDLE_REQUEST)

    else:
        try:

            key_bundle = {
                "IPK": keys.get("IPK"),
                "SPK": keys.get("SPK"),
                "OPK": keys.get("OPKs")[0],
                "sigma": keys.get("sigma")
            }

            keys.get("OPKs").pop(0)
            server.database.save()

            server.send(message.sender, {"status": SUCCESS, "key_bundle": key_bundle, "owner": target}, X3DH_BUNDLE_REQUEST)

        except Exception:
            traceback.print_exc()
            debug(f"Failed to send keys to {message.sender}.")

def handle_x3dh_key_shortage(server, message: Message, client: SSLSocket, addr: tuple[str, int]):
    """Called when a user sends new keys because they ran out of one-time prekeys."""
    OPKs = message.dict().get("OPKs")
    if not OPKs or not isinstance(OPKs, list) or len(OPKs) == 0 or not all(isinstance(OPK, VerifyingKey) for OPK in OPKs):
        debug(f"{message.sender} ({addr}) sent new OPKs, but the list is invalid.")
        server.send(message.sender, {"status": ERROR, "error": "Invalid OPKs."}, X3DH_REQUEST_KEYS)
    else:
        debug(f"{message.sender} ({addr}) sent new keys. Saving them.")
        server.database.get(message.sender).get("keys").get("OPKs").extend(OPKs)
        server.send(message.sender, {"status": SUCCESS}, X3DH_REQUEST_KEYS)

def handle_x3dh_forward(server, message: Message, client: SSLSocket, addr: tuple[str, int]):
    """Called after the client received a key bundle and wants to react to it so the other user can be notified."""
    target = message.dict().get("target")
    sender = message.sender
    if not target or not check_username(target):
        debug(f"{message.sender} ({addr}) wants to forward an x3dh message without a valid target.")
        server.send(message.sender, {"status": ERROR, "error": "No valid target specified."}, X3DH_FORWARD)
        return

    if not server.is_registered(target):
        debug(f"{message.sender} ({addr}) wants to forward an x3dh message to an unregistered user ({target}).")
        server.send(message.sender, {"status": ERROR, "error": f"{target} is not registered."}, X3DH_FORWARD)
        return

    # Add the sender to the message, so the receiver knows who sent the message
    message.dict()["sender"] = sender

    if server.is_logged_in(target):
        debug(f"{message.sender} ({addr}) forwarded an x3dh message to {target}.")
        server.send(target, message.dict(), X3DH_FORWARD)
    else:
        debug(f"{message.sender} ({addr}) forwarded an x3dh message to offline user {target}. Saving it for later.")
        server.add_offline_message(target, Message(serializer.encode_message(message.dict()), "server", target, X3DH_FORWARD))
