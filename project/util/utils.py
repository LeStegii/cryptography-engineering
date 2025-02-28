import threading
import time


def debug(message: str) -> None:
    curr_thread = threading.current_thread()
    print(f"[{time.strftime('%H:%M:%S', time.localtime())}] {curr_thread.name}: {message}")


def check_username(username: str) -> bool:
    """Check if the username is valid."""
    return isinstance(username, str) and username.isalnum() and 1 <= len(username) <= 16