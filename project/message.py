from typing import Optional

import utils

MESSAGE = "message"
FORWARD = "forward"
REGISTER = "register"
LOGIN = "login"
EXIT = "exit"
STATUS = "status_request"
IDENTITY = "identity"

REQUEST_SALT = "request_salt"
ANSWER_SALT = "answer_salt"
SEND_PASSWORD = "send_password"

ERROR = "error"
SUCCESS = "success"


class Message:
    def __init__(self, message: str | bytes, sender: str, receiver: str, type: str = MESSAGE):
        self.content = message
        self.sender = sender
        self.receiver = receiver
        self.type = type

    def __str__(self):
        return f"{self.sender} -> {self.receiver}: {self.content} ({self.type})"

    def __repr__(self):
        return self.__str__()

    def to_bytes(self) -> bytes:
        return utils.encode_message({
            "content": self.content,
            "sender": self.sender,
            "receiver": self.receiver,
            "type": self.type
        })

    def dict(self) -> dict[str, any]:
        return utils.decode_message(self.content)

    @staticmethod
    def from_bytes(data: bytes) -> Optional["Message"]:
        try:
            message = utils.decode_message(data)
            return Message(message["content"], message["sender"], message["receiver"], message["type"])
        except:
            return None