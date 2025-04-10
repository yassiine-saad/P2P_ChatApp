# import struct
# from cryptography.hazmat.primitives.asymmetric import ed25519
# from cryptography.exceptions import InvalidSignature

# PACKET_TYPE_DISCOVERY = 1


# def create_discovery_announce(username: str, ip_address: str, public_key_bytes: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
#     username_bytes = username.encode('utf-8')
#     ip_bytes = ip_address.encode('utf-8')

#     # Construction du payload (sans timeout)
#     payload = struct.pack(
#         f'!B'                           # type
#         f'B{len(username_bytes)}s'     # username
#         f'B{len(ip_bytes)}s'           # IP
#         f'B{len(public_key_bytes)}s',  # Public key
#         PACKET_TYPE_DISCOVERY,
#         len(username_bytes), username_bytes,
#         len(ip_bytes), ip_bytes,
#         len(public_key_bytes), public_key_bytes,
#     )

#     # Signature du payload
#     signature = private_key.sign(payload)

#     return payload + signature


# def parse_discovery_announce(data: bytes) -> dict:
#     try:
#         if len(data) < 10:
#             raise ValueError("Données trop courtes")

#         offset = 0

#         # Type
#         packet_type = data[offset]
#         offset += 1

#         if packet_type != PACKET_TYPE_DISCOVERY:
#             raise ValueError(f"Type de paquet inconnu : {packet_type}")

#         # Username
#         u_len = data[offset]
#         offset += 1
#         username = data[offset:offset + u_len].decode()
#         offset += u_len

#         # IP Address
#         ip_len = data[offset]
#         offset += 1
#         ip_address = data[offset:offset + ip_len].decode()
#         offset += ip_len

#         # Public Key
#         key_len = data[offset]
#         offset += 1
#         public_key_bytes = data[offset:offset + key_len]
#         offset += key_len

#         # Signature
#         signature = data[offset:]
#         payload = data[:offset]

#         # Vérification de la signature
#         public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
#         public_key.verify(signature, payload)

#         return {
#             "type": packet_type,
#             "username": username,
#             "ip": ip_address,
#             "public_key": public_key,
#             "signature": signature
#         }

#     except (IndexError, ValueError, UnicodeDecodeError, InvalidSignature) as e:
#         raise ValueError(f"Erreur parsing ou vérification : {e}")


# def is_discovery_packet(data: bytes) -> bool:
#     # Vérifie que le type est DISCOVERY et que le paquet est plausible
#     return data and len(data) >= 10 and data[0] == PACKET_TYPE_DISCOVERY




import struct
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

PACKET_TYPE_DISCOVERY = 1


def create_discovery_announce(username: str, ip_address: str,
                              ed25519_pub: bytes, x25519_pub: bytes,
                              private_key: ed25519.Ed25519PrivateKey) -> bytes:
    username_bytes = username.encode('utf-8')
    ip_bytes = ip_address.encode('utf-8')

    # Payload sans signature
    payload = struct.pack(
        f'!B'  # Type
        f'B{len(username_bytes)}s'
        f'B{len(ip_bytes)}s'
        f'B{len(ed25519_pub)}s'
        f'B{len(x25519_pub)}s',
        PACKET_TYPE_DISCOVERY,
        len(username_bytes), username_bytes,
        len(ip_bytes), ip_bytes,
        len(ed25519_pub), ed25519_pub,
        len(x25519_pub), x25519_pub
    )

    signature = private_key.sign(payload)

    return payload + signature


def parse_discovery_announce(data: bytes) -> dict:
    try:
        offset = 0

        # Type
        packet_type = data[offset]
        offset += 1
        if packet_type != PACKET_TYPE_DISCOVERY:
            raise ValueError("Type de paquet invalide")

        # Username
        u_len = data[offset]
        offset += 1
        username = data[offset:offset + u_len].decode()
        offset += u_len

        # IP address
        ip_len = data[offset]
        offset += 1
        ip = data[offset:offset + ip_len].decode()
        offset += ip_len

        # Ed25519 public key
        ed_len = data[offset]
        offset += 1
        ed25519_pub_bytes = data[offset:offset + ed_len]
        offset += ed_len

        # X25519 public key
        x_len = data[offset]
        offset += 1
        x25519_pub_bytes = data[offset:offset + x_len]
        offset += x_len

        # Signature
        signature = data[offset:]
        payload = data[:offset]

        # Vérification de la signature
        ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(ed25519_pub_bytes)
        ed_pub.verify(signature, payload)

        return {
            "type": packet_type,
            "username": username,
            "ip": ip,
            "ed25519_public_key": ed_pub,
            "x25519_public_key_bytes": x25519_pub_bytes,
            "signature": signature
        }

    except (IndexError, ValueError, UnicodeDecodeError, InvalidSignature) as e:
        raise ValueError(f"[!] Erreur parsing ou vérification DISCOVERY: {e}")


def is_discovery_packet(data: bytes) -> bool:
    return data and len(data) >= 10 and data[0] == PACKET_TYPE_DISCOVERY
