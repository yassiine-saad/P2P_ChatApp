import struct
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

PACKET_TYPE_DISCOVERY = 1

def create_discovery_announce(username: str, ip_address: str, public_key_bytes: bytes, timeout: int, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    username_bytes = username.encode('utf-8')
    ip_bytes = ip_address.encode('utf-8')

    # Construction du payload (sans signature)
    payload = struct.pack(
        f'!B'                           # type
        f'B{len(username_bytes)}s'     # username
        f'B{len(ip_bytes)}s'           # ip address
        f'B{len(public_key_bytes)}s'   # public key
        f'I',                          # timeout
        PACKET_TYPE_DISCOVERY,
        len(username_bytes), username_bytes,
        len(ip_bytes), ip_bytes,
        len(public_key_bytes), public_key_bytes,
        timeout
    )

    # Signature du payload
    signature = private_key.sign(payload)

    return payload + signature




def parse_discovery_announce(data: bytes) -> dict:
    try:
        if len(data) < 10:
            raise ValueError("Données trop courtes")

        offset = 0

        # Type
        packet_type = data[offset]
        offset += 1

        if packet_type != PACKET_TYPE_DISCOVERY:
            raise ValueError(f"Type de paquet inconnu : {packet_type}")

        # Username
        u_len = data[offset]
        offset += 1
        username = data[offset:offset + u_len].decode()
        offset += u_len

        # IP Address
        ip_len = data[offset]
        offset += 1
        ip_address = data[offset:offset + ip_len].decode()
        offset += ip_len

        # Public Key
        key_len = data[offset]
        offset += 1
        public_key_bytes = data[offset:offset + key_len]
        offset += key_len

        # Timeout
        if len(data) < offset + 4:
            raise ValueError("Données incomplètes pour timeout")
        timeout = struct.unpack('!I', data[offset:offset + 4])[0]
        offset += 4

        # Signature
        signature = data[offset:]
        payload = data[:offset]

        # Vérification de la signature
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, payload)

        return {
            "type": packet_type,
            "username": username,
            "ip": ip_address,
            "public_key": public_key,
            "timeout": timeout,
            "signature": signature
        }

    except (IndexError, ValueError, UnicodeDecodeError, InvalidSignature) as e:
        raise ValueError(f"Erreur parsing ou vérification : {e}")


# def is_discovery_packet(data: bytes) -> bool:
#     if not data or len(data) < 1:
#         return False
#     return data[0] == PACKET_TYPE_DISCOVERY


def is_discovery_packet(data: bytes) -> bool:
    # Vérifie que le type est bien DISCOVERY et qu'il y a au moins 10 octets (1 pour type + ...)
    return len(data) >= 10 and data[0] == PACKET_TYPE_DISCOVERY
