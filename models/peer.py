class Peer:
    def __init__(self, peer_name, ip_address, public_key, port=None,unread_messages=0):
        self.peer_name = peer_name
        self.ip_address = ip_address
        self.public_key = public_key
        self.port = None
        self.last_seen = None
        self.unread_messages: int = 0

    def __repr__(self):
        return f"{self.peer_name}@{self.ip_address}:{self.port}" if self.port else f"{self.peer_name}@{self.ip_address}"

    def __eq__(self, other):
        if isinstance(other, Peer):
            return self.ip_address == other.ip_address
        return False

    def __hash__(self):
        return hash(self.ip_address)

