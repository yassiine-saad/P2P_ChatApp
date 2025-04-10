from datetime import datetime

from models.peer import Peer

class Message:
    def __init__(self, content: str, is_sent: bool, sender: Peer):
        self.content = content
        self.is_sent = is_sent
        self.sender = sender
        self.timestamp = datetime.now()

    def __str__(self):
        sender_info = "Moi" if self.is_sent else f"{self.sender.peer_name}@{self.sender.ip_address}:{self.sender.port}"
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {sender_info}: {self.content}"
