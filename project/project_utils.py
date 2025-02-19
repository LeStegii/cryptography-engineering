from project.message import Message


def is_valid_message(message: Message) -> bool:
    if not message:
        return False

    if not message.sender or not message.receiver or not message.type:
        return False

    try:
        message.dict()
    except:
        return False

    return True