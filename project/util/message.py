from traceback import print_exc
from typing import Optional

from project.util import utils

MESSAGE = "message"
FORWARD = "forward"
REGISTER = "register"
LOGIN = "login"
EXIT = "exit"
STATUS = "status_request"
IDENTITY = "identity"

NOT_REGISTERED = "not_registered"
REGISTERED = "registered"

REQUEST_SALT = "request_salt"
ANSWER_SALT = "answer_salt"
SEND_PASSWORD = "send_password"

ERROR = "error"
SUCCESS = "success"
REQUEST = "request"

X3DH_BUNDLE_REQUEST = "x3dh_request"
X3DH_FORWARD = "x3dh_reaction"
X3DH_REQUEST_KEYS = "x3dh_keys"

RESET = "reset"

class Message:

    def __init__(self, message: bytes, sender: str, receiver: str, type: str = MESSAGE):
        self.content = message
        self.sender = sender
        self.receiver = receiver
        self.type = type
        self.content_dict = None

    def __str__(self):
        return f"{self.sender} -> {self.receiver}: {self.content} ({self.type})"

    def __repr__(self):
        return self.__str__()

    def to_bytes(self) -> bytes:
        from project.util.serializer.serializer import encode_message
        return encode_message({
            "content": self.content,
            "sender": self.sender,
            "receiver": self.receiver,
            "type": self.type
        })

    def dict(self) -> dict[str, any]:
        from project.util.serializer.serializer import decode_message
        if not self.content_dict:
            self.content_dict = decode_message(self.content)
        return self.content_dict

    @staticmethod
    def from_bytes(data: bytes) -> Optional["Message"]:
        from project.util.serializer.serializer import decode_message
        try:
            message = decode_message(data)
            return Message(message["content"], message["sender"], message["receiver"], message["type"])
        except:
            print_exc()
            return None


def is_valid_message(message) -> bool:
    if not message:
        return False

    if not message.sender or not message.receiver or not message.type:
        return False

    if not isinstance(message.sender, str) or not isinstance(message.receiver, str) or not isinstance(message.type, str):
        return False

    if not utils.check_username(message.sender) or not utils.check_username(message.receiver):
        return False

    try:
        message.dict()
        return True
    except:
        print_exc()
        return False