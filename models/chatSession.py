from typing import List
from models.message import Message
from models.peer import Peer

class ChatSession:
    def __init__(self, peer: Peer, socket_connection):
        self.peer = peer
        self.socket = socket_connection  # Le socket dédié à cette session
        self.messages: List[Message] = []

    def add_message(self, message: Message):
        self.messages.append(message)

    def get_history(self):
        return [str(msg) for msg in self.messages]


