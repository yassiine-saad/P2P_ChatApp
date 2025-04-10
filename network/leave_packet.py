import struct
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

PACKET_TYPE_LEAVE = 2

def create_leave_packet(ip_address: str, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    ip_bytes = ip_address.encode('utf-8')

    # Construction du payload
    payload = struct.pack(
        f'!B'                          # type
        f'B{len(ip_bytes)}s',         # ip address
        PACKET_TYPE_LEAVE,
        len(ip_bytes), ip_bytes
    )

    # Signature
    signature = private_key.sign(payload)

    return payload + signature


def parse_leave_packet(data: bytes) -> dict:
    try:
        if len(data) < 3:
            raise ValueError("Données trop courtes pour un paquet LEAVE")

        offset = 0
        packet_type = data[offset]
        offset += 1

        if packet_type != PACKET_TYPE_LEAVE:
            raise ValueError(f"Type de paquet incorrect : {packet_type}")

        ip_len = data[offset]
        offset += 1

        ip_address = data[offset:offset + ip_len].decode()
        offset += ip_len

        signature = data[offset:]
        payload = data[:offset]

        # On ne peut pas vérifier la signature sans la clé publique
        # Tu peux adapter ça selon ton système (si tu as une table IP → clé publique)
        return {
            "type": packet_type,
            "ip": ip_address,
            "signature": signature,
            "payload": payload  # utile si tu veux vérifier après
        }

    except (IndexError, ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"Erreur parsing LEAVE : {e}")


def is_leave_packet(data: bytes) -> bool:
    return len(data) >= 2 and data[0] == PACKET_TYPE_LEAVE
