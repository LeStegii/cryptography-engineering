from ecdsa import SigningKey, VerifyingKey

from project.util import crypto_utils, x3dh_utils
from project.util.message import Message, ERROR, X3DH_FORWARD, SUCCESS, X3DH_REQUEST_KEYS
from project.util.utils import debug


def handle_x3dh_bundle_answer(client, message: Message) -> bool:
    """
    Called after receiving a key bundle from the server.
    The key bundle is received after requesting it from the server.
    """
    content = message.dict()

    if content.get("status") == ERROR:
        debug(f"Failed to request key bundle: {content.get("error")}")
        return True

    key_bundle_b = content.get("key_bundle")
    if not key_bundle_b:
        debug(f"Received invalid key bundle for {content.get("owner")} from server.")
        return True

    keys = client.load_or_gen_keys()
    ik_A: SigningKey = keys["ik"]
    IPK_A: VerifyingKey = keys["IPK"]
    OPK_A: VerifyingKey = keys["OPKs"][0]

    sigma_B: bytes = key_bundle_b.get("sigma")
    IPK_B: VerifyingKey = key_bundle_b.get("IPK")
    SPK_B: VerifyingKey = key_bundle_b.get("SPK")
    OPK_B: VerifyingKey = key_bundle_b.get("OPK")

    if not crypto_utils.ecdsa_verify(sigma_B, SPK_B.to_pem(), IPK_B):
        debug("Invalid signature for SPK_B. Aborting X3DH.")
    else:
        debug("Computing shared secret...")
        ek_A, EPK_A = crypto_utils.generate_signature_key_pair()
        shared_secret = x3dh_utils.x3dh_key(ik_A, ek_A, IPK_B, SPK_B, OPK_B)
        client.database.update("shared_secrets", {content.get("owner"): shared_secret})
        debug("Sending reaction to server...")
        debug(f"Shared secret computed and saved for {content.get('owner')}: {shared_secret.hex()}")
        iv, cipher, tag = crypto_utils.aes_gcm_encrypt(shared_secret, client.username.encode(), IPK_A.to_pem() + IPK_B.to_pem())
        client.send("server", {
            "target": content.get("owner"),
            "IPK": IPK_A,
            "EPK": EPK_A,
            "OPK": OPK_A,
            "iv": iv,
            "cipher": cipher,
            "tag": tag
        }, X3DH_FORWARD)

    return True


def handle_x3dh_forward(client, message: Message) -> bool:
    content = message.dict()
    debug(f"Received a forwarded x3dh message for {content.get('target')} from server.")

    keys = client.load_or_gen_keys()
    ik_B: SigningKey = keys["ik"]
    sk_B: SigningKey = keys["sk"]
    ok_B: SigningKey = keys["oks"][0]
    IPK_B: VerifyingKey = keys["IPK"]
    IPK_A: VerifyingKey = content.get("IPK")
    EPK_A: VerifyingKey = content.get("EPK")
    OPK_A: VerifyingKey = content.get("OPK")
    iv: bytes = content.get("iv")
    cipher: bytes = content.get("cipher")
    tag: bytes = content.get("tag")
    sender: str = content.get("sender")
    keys.get("oks").pop(0)
    keys.get("OPKs").pop(0)
    client.database.save()
    if len(keys.get("oks")) == 0:
        debug("No more one time prekeys left.")

    shared_secret = x3dh_utils.x3dh_key_reaction(IPK_A, EPK_A, ik_B, sk_B, ok_B)
    try:
        decrypted = crypto_utils.aes_gcm_decrypt(shared_secret, iv, cipher, IPK_A.to_pem() + IPK_B.to_pem(), tag)
        if decrypted == sender.encode():
            debug(f"Succesfully computed shared secret with {sender}: {shared_secret.hex()}")
            client.database.update("shared_secrets", {sender: shared_secret})
        else:
            debug(f"Failed to decrypt message from {sender}. Generating shared secret failed.")

        return True
    except Exception as e:
        debug(f"Failed to decrypt message from {sender}. Generating shared secret failed.")
        return True


def handle_x3dh_key_request(client, message: Message) -> bool:
    """Called when the server doesn't have one time prekeys for the user."""

    if message.dict().get("status") == ERROR:
        debug("Failed to request key bundle from server.")
        return True
    elif message.dict().get("status") == SUCCESS:
        debug("Server accepted new one time prekeys.")
        return True

    keys = crypto_utils.generate_one_time_pre_keys(5)
    oks = [ok for ok, _ in keys]

    OPKs = [OPK for _, OPK in keys]

    client.load_or_gen_keys()["OPKs"].extend(OPKs)
    client.load_or_gen_keys()["oks"].extend(oks)
    client.send("server", {"OPKs": OPKs}, X3DH_REQUEST_KEYS)
    client.database.save()
    return True
