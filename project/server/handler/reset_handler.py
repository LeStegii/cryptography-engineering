from ssl import SSLSocket

from project.util.message import *
from project.util.serializer import serializer
from project.util.utils import debug


def handle_reset(server, message: Message, client: SSLSocket, addr: tuple[str, int]):
    receiver = message.dict().get("target")

    if receiver == "server":
        debug(f"{message.sender} ({addr}) sent a reset request.")
        server.database.delete(message.sender)
        for user in server.database.keys():
            if server.is_logged_in(user):
                server.send(user, {"sender": message.sender, "status": REQUEST}, RESET)
            else:
                server.add_offline_message(user, Message(serializer.encode_message({"sender": message.sender, "status": REQUEST}), "server", user, RESET))
        raise Exception("User reset.")

    if not utils.check_username(receiver) or not server.is_registered(receiver):
        debug(f"{message.sender} ({addr}) tried to send a reset message to an invalid user ({receiver}).")
        server.send(message.sender, {"status": ERROR, "error": f"{receiver} is invalid."}, RESET)
        return

    debug(f"{message.sender} ({addr}) sent a reset message to {message.receiver}.")
    if server.is_logged_in(receiver):
        server.send(receiver, {"sender": message.sender, "status": REQUEST}, RESET)
    else:
        server.add_offline_message(receiver, Message(serializer.encode_message({"sender": message.sender, "status": REQUEST}), "server", receiver, RESET))