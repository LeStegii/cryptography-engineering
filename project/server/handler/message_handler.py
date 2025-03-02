from ssl import SSLSocket

from project.util.message import *
from project.util.utils import debug


def handle_message(server, message: Message, client: SSLSocket, addr: tuple[str, int]):
    if not server.is_registered(message.receiver):
        debug(f"{message.sender} ({addr}) tried to send a message to an unregistered user ({message.receiver}).")
        server.send(message.sender, {"status": ERROR, "error": f"{message.receiver} is not registered."}, MESSAGE)
        return

    if not server.is_logged_in(message.receiver):
        debug(f"{message.sender} ({addr}) sent a message to offline user {message.receiver}. Saving it for later.")
        server.add_offline_message(message.receiver, message)
        return

    debug(f"{message.sender} ({addr}) sent a message to {message.receiver}.")
    server.send_bytes(message.to_bytes(), message.receiver)  # Forward the message to the recipient
