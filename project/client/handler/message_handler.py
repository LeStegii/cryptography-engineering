from ecdsa import VerifyingKey

from project.util.message import Message, ERROR
from project.util.ratchet import DoubleRatchetState
from project.util.utils import debug


def send_message(client, receiver: str, plaintext: str) -> bool:
    if not plaintext or len(plaintext.strip()) == 0:
        debug("Empty messages aren't allowed.")
        return True

    if not client.database.has("chats"):
        client.database.insert("chats", {})

    if not init_chat_sender(client, receiver):
        return False

    if not client.database.has("chats") or not client.database.get("chats").get(receiver):
        debug(f"No shared secret found for {receiver}. Initiate a chat using 'init {receiver}'.")
        return False

    drs = client.database.get("chats").get(receiver)
    message = drs.encrypt(plaintext.encode())
    client.send(receiver, message)
    client.database.save()
    return True


def handle_message(client, message: Message) -> bool:

    if message.sender == "server":
        if message.dict().get("status") == ERROR:
            debug(f"Error from server: {message.dict().get('error')}")
        else:
            debug(f"Server: {message.dict().get('message')}")
        return True

    else:
        content = message.dict()
        sender = message.sender
        database = client.database

        init_chat_receiver(client, sender)

        drs = database.get("chats").get(sender)
        try:
            plaintext = drs.decrypt(content)
            debug(f"{sender}: {plaintext.decode()}")
        except Exception as e:
            debug(f"Failed to decrypt message from {sender}.")
            return True
        client.database.save()

        return True

def init_chat_sender(client, receiver: str) -> bool:
    if not client.database.has("chats"):
        client.database.insert("chats", {})

    if not client.database.get("chats").get(receiver):

        if not client.database.has("shared_secrets") or not client.database.get("shared_secrets").get(receiver):
            debug(f"No shared secret found for {receiver}. Initiate a chat using 'init {receiver}'.")
            return False

        if not client.database.has("key_bundles") or not client.database.get("key_bundles").get(receiver):
            debug(f"No key bundle found for {receiver}.")
            return False
        SPK_B: VerifyingKey = client.database.get("key_bundles").get(receiver).get("SPK")
        root_key = client.database.get("shared_secrets").get(receiver)
        # Remove the shared secret from the database
        client.database.get("shared_secrets").pop(receiver)
        client.database.save()

        drs = DoubleRatchetState(root_key, None, None, SPK_B, initialized_by_me=True)
        client.database.update("chats", {receiver: drs})

    return True

def init_chat_receiver(client, sender: str) -> bool:
    if not client.database.has("chats"):
        client.database.insert("chats", {})

    if not client.database.has("shared_secrets") or not client.database.get("shared_secrets").get(sender):
        return False

    root_key = client.database.get("shared_secrets").get(sender)
    # Remove the shared secret from the database
    client.database.get("shared_secrets").pop(sender)
    client.database.save()

    if not client.database.get("chats").get(sender):
        sk, SPK = client.database.get("keys").get("sk"), client.database.get("keys").get("SPK")
        drs = DoubleRatchetState(root_key, sk, SPK, initialized_by_me=False)
        client.database.update("chats", {sender: drs})

    return True