from ssl import SSLSocket

from project.util.message import IDENTITY, ERROR, STATUS, NOT_REGISTERED, REGISTERED, Message
from project.util.utils import debug, check_username
from project.util.message import is_valid_message


def check_identity(server, client_socket: SSLSocket, addr: tuple[str, int]) -> bool:
    """
    Checks the initial message sent by the client.
    The initial message has to be of type 'identity' and contain a username.
    :param client_socket The user's socket
    :param addr: The user's address
    :return Whether the check was successful
    """
    received_bytes = client_socket.recv(1024)
    debug("Received bytes.")

    if not received_bytes:
        debug(f"{addr}'s first message was empty.")
        return False

    message = Message.from_bytes(received_bytes)

    if not is_valid_message(message):
        debug(f"{addr}'s first message couldn't be decoded.")
        return False

    if message.type != IDENTITY:
        server.send(client_socket, {"status": ERROR, "error": "You must send an identity message first."}, STATUS)
        debug(f"{addr} didn't send an identy message as their first message.")
        return False

    username = message.dict().get("username")

    if not message.sender or not message.sender == username or not check_username(username):
        server.send(client_socket, {"status": ERROR, "error": "You must send a valid identity message."}, STATUS)
        debug(f"{addr} did not send a valid identity message (error with username).")
        return False

    if server.connections.get(username):
        server.send(client_socket, {"status": ERROR, "error": "A user with this name is already connected."}, STATUS)
        debug(f"{addr} tried to connect as {username}, but a user with this name is already connected.")
        return False

    server.connections[message.sender] = addr
    server.sockets[addr] = client_socket

    if not server.is_registered(username):
        debug(f"{message.sender} ({addr}) sent a status request, User is currently not registered.")
        server.send(message.sender, {"status": NOT_REGISTERED}, STATUS)
    else:
        debug(f"{message.sender} ({addr}) sent a status request, User is registered.")
        server.send(message.sender, {"status": REGISTERED}, STATUS)
    return True
