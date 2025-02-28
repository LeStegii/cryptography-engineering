from project.util.message import Message, is_valid_message, ERROR
from project.util.utils import debug


def handle_message(client, message: Message) -> bool:
    if not is_valid_message(message):
        debug(f"Received invalid message from {message.sender}.")

    if message.sender == "server":
        if message.dict().get("status") == ERROR:
            debug(f"Error from server: {message.dict().get('error')}")
        else:
            debug(f"Server: {message.dict().get('message')}")
        return True

    content = message.dict().get("message")
    if not content:
        debug(f"Received empty message from {message.sender}.")
    else:
        debug(f"{message.sender}: {content}")
    return True
