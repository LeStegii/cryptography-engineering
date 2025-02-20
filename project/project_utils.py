import threading
import time

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
        return False


def debug(message: str) -> None:
    curr_thread = threading.current_thread()
    print(f"[{time.strftime('%H:%M:%S', time.localtime())}] {curr_thread.name}: {message}")

def check_username(username: str) -> bool:
    """Check if the username is valid."""
    return isinstance(username, str) and username.isalnum() and 4 <= len(username) <= 16