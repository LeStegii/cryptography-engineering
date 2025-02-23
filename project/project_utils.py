import threading
import time
from traceback import print_exc

import utils
from project.message import Message


def is_valid_message(message: Message) -> bool:
    if not message:
        return False

    if not message.sender or not message.receiver or not message.type:
        return False

    try:
        message.dict()
        return True
    except:
        print_exc()
        return False


def debug(message: str) -> None:
    curr_thread = threading.current_thread()
    print(f"[{time.strftime('%H:%M:%S', time.localtime())}] {curr_thread.name}: {message}")

def check_username(username: str) -> bool:
    """Check if the username is valid."""
    return isinstance(username, str) and username.isalnum() and 1 <= len(username) <= 16


def generate_initial_x3dh_keys():
    ik, IPK = utils.generate_signature_key_pair()
    sk, SPK = utils.generate_signature_key_pair()
    one_time_prekeys = generate_one_time_pre_keys(5)

    return {
        "ik": ik,
        "IPK": IPK,
        "sk": sk,
        "SPK": SPK,
        "sigma": utils.ecdsa_sign(SPK.to_pem(), ik),
        "oks": [ok for ok, _ in one_time_prekeys],
        "OPKs": [OPK for _, OPK in one_time_prekeys]
    }


def generate_one_time_pre_keys(amount: int):
    one_time_prekeys = []
    for i in range(amount):
        ok, OPK = utils.generate_signature_key_pair()
        one_time_prekeys.append((ok, OPK))
    return one_time_prekeys
