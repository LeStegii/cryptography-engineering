import utils

MESSAGE = "message"


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

    @staticmethod
    def from_bytes(data: bytes) -> "Message":
        message = utils.decode_message(data)
        return Message(message["content"], message["sender"], message["receiver"], message["type"])