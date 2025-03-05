from project.util.message import Message, RESET, REQUEST, ERROR
from project.util.utils import debug


def handle_reset(client, message: Message) -> bool:
    if message.dict().get("status") == REQUEST:
        sender = message.dict().get("sender")
        debug(f"Received reset request from {message.sender}.")
        return clear_from_db(client, sender)

    elif message.dict().get("status") == ERROR:
        debug(f"Error resetting user: {message.dict().get('error')}")
    return True


def reset(client, receiver: str):
    debug(f"Sending reset request to server for {receiver}.")
    client.send("server", {"target": receiver}, RESET)
    if receiver != "server":
        clear_from_db(client, receiver)
    else:
        client.database.clear()


def clear_from_db(client, receiver: str):
    if client.database.get("shared_secrets") and client.database.get("shared_secrets").get(receiver):
        client.database.get("shared_secrets").pop(receiver)
    if client.database.get("key_bundles") and client.database.get("key_bundles").get(receiver):
        client.database.get("key_bundles").pop(receiver)
    if client.database.get("chats") and client.database.get("chats").get(receiver):
        client.database.get("chats").pop(receiver)
    client.database.save()
    debug(f"Deleted shared secret, chat and key bundle with {receiver} from the database.")
    return True
