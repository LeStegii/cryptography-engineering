from project.util import crypto_utils
from project.util.crypto_utils import power_sk_vk, KDF
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

    else:
        content = message.dict()
        sender = message.sender
        database = client.database

        if not database.get("chats"):
            database.insert("chats", {})

        if sender not in database.get("chats"):
            debug(f"No chat history with {sender}, initializing...")
            database.insert("chats", {sender: []})

        chat = database.get("chats")[sender]

        if not chat or chat[-1].get("last") == "ME":
            # New ratchet step: Compute new shared key
            X = content["X"]
            if not chat:
                # First message from sender, no prior state
                y, Y = crypto_utils.generate_signature_key_pair()
                database.insert("key_bundles", {sender: {"SPK": Y}})
            else:
                y = chat[-1].get("x")

            DH = power_sk_vk(y, X)  # Compute DH using our private key and sender's public key
            ck = chat[-1].get("ck") if chat else database.get("shared_secrets").get(sender)

            ck1, mk1 = KDF(DH, ck)  # Derive new chain key and message key
            chat.append({"X": X, "last": "THEM", "ck": ck1, "Y": Y, "x": y})

        else:
            # Continue existing message chain
            ck = chat[-1].get("ck")
            ck1, mk1 = KDF(b"\x00" * 32, ck)  # No new DH exchange

        # Decrypt message
        iv, cipher, tag = content["iv"], content["cipher"], content["tag"]
        try:
            plaintext = crypto_utils.aes_gcm_decrypt(mk1, cipher, iv, sender.encode(), tag)
            print(f"Message from {sender}: {plaintext.decode()}")
        except Exception as e:
            debug(f"Decryption failed: {e}")
            return False

        # Store updated state
        chat.append({"X": chat[-1].get("X"), "last": "THEM", "ck": ck1, "Y": chat[-1].get("Y"), "x": chat[-1].get("x")})
        database.insert("chats", {sender: chat})

        return True
