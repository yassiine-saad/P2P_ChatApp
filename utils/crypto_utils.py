# import os
# import base64
# import hashlib

# from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# # ------------ CLÉS PERSISTENTES ------------

# KEYS_FOLDER = os.path.expanduser("~/.chatapp_keys")
# PRIVATE_KEY_FILE = os.path.join(KEYS_FOLDER, "private_key.pem")
# PUBLIC_KEY_FILE = os.path.join(KEYS_FOLDER, "public_key.pem")

# def save_keys_to_disk(private_key, public_key):
#     os.makedirs(KEYS_FOLDER, exist_ok=True)
#     with open(PRIVATE_KEY_FILE, "wb") as f:
#         f.write(private_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=serialization.NoEncryption()
#         ))

#     with open(PUBLIC_KEY_FILE, "wb") as f:
#         f.write(public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ))

# def load_keys_from_disk():
#     if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
#         return None, None

#     with open(PRIVATE_KEY_FILE, "rb") as f:
#         private_key = serialization.load_pem_private_key(f.read(), password=None)

#     with open(PUBLIC_KEY_FILE, "rb") as f:
#         public_key = private_key.public_key()

#     return private_key, public_key

# def get_or_create_keys():
#     priv, pub = load_keys_from_disk()
#     if priv is None or pub is None:
#         priv, pub = ed25519.Ed25519PrivateKey.generate(), None
#         pub = priv.public_key()
#         save_keys_to_disk(priv, pub)
#     return priv, pub

# # ------------ SÉRIALISATION ------------

# def serialize_public_key(public_key):
#     return public_key.public_bytes(
#         encoding=serialization.Encoding.Raw,
#         format=serialization.PublicFormat.Raw
#     )

# def deserialize_public_key(data):
#     return ed25519.Ed25519PublicKey.from_public_bytes(data)

# # ------------ CHIFFREMENT / DÉCHIFFREMENT ------------

# def generate_x25519_keys():
#     private_key = x25519.X25519PrivateKey.generate()
#     public_key = private_key.public_key()
#     return private_key, public_key

# def derive_shared_key(private_key, peer_public_key_bytes):
#     peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
#     shared_secret = private_key.exchange(peer_public_key)

#     hkdf = HKDF(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=None,
#         info=b'handshake data',
#     )
#     return hkdf.derive(shared_secret)

# def encrypt_message(message: str, peer_public_key_bytes: bytes, sender_private_key: ed25519.Ed25519PrivateKey):
#     ephemeral_priv, ephemeral_pub = generate_x25519_keys()
#     shared_key = derive_shared_key(ephemeral_priv, peer_public_key_bytes)

#     nonce = os.urandom(12)
#     cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce))
#     encryptor = cipher.encryptor()
#     ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

#     signature = sender_private_key.sign(ciphertext)

#     return (
#         ephemeral_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
#         + nonce
#         + encryptor.tag
#         + signature
#         + ciphertext
#     )

# def decrypt_message(data: bytes, receiver_private_key: ed25519.Ed25519PrivateKey, sender_public_key: ed25519.Ed25519PublicKey):
#     ephemeral_pub = data[:32]
#     nonce = data[32:44]
#     tag = data[44:60]
#     signature = data[60:60 + 64]
#     ciphertext = data[60 + 64:]

#     raw_private_bytes = receiver_private_key.private_bytes(
#         encoding=serialization.Encoding.Raw,
#         format=serialization.PrivateFormat.Raw,
#         encryption_algorithm=serialization.NoEncryption()
#     )
#     x25519_priv = x25519.X25519PrivateKey.from_private_bytes(raw_private_bytes[:32])
#     shared_key = derive_shared_key(x25519_priv, ephemeral_pub)

#     sender_public_key.verify(signature, ciphertext)  # Throws exception if invalid

#     cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce, tag))
#     decryptor = cipher.decryptor()
#     plaintext = decryptor.update(ciphertext) + decryptor.finalize()
#     return plaintext.decode()

# # ------------ EMPREINTE (IDENTITÉ) ------------

# def get_fingerprint(public_key_bytes: bytes) -> str:
#     return hashlib.sha256(public_key_bytes).hexdigest()



import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

# ------------ CLÉS PERSISTENTES ------------

KEYS_FOLDER = os.path.expanduser("~/.chatapp_keys")
ED25519_PRIV_FILE = os.path.join(KEYS_FOLDER, "ed25519_private_key.pem")
X25519_PRIV_FILE = os.path.join(KEYS_FOLDER, "x25519_private_key.pem")


def save_keys_to_disk(ed_priv, x_priv):
    os.makedirs(KEYS_FOLDER, exist_ok=True)

    with open(ED25519_PRIV_FILE, "wb") as f:
        f.write(ed_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(X25519_PRIV_FILE, "wb") as f:
        f.write(x_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))


def load_keys_from_disk():
    if not os.path.exists(ED25519_PRIV_FILE) or not os.path.exists(X25519_PRIV_FILE):
        return None, None

    with open(ED25519_PRIV_FILE, "rb") as f:
        ed_priv = serialization.load_pem_private_key(f.read(), password=None)

    with open(X25519_PRIV_FILE, "rb") as f:
        x_priv = serialization.load_pem_private_key(f.read(), password=None)

    return ed_priv, x_priv


def get_or_create_keys():
    ed_priv, x_priv = load_keys_from_disk()
    if ed_priv is None or x_priv is None:
        ed_priv = ed25519.Ed25519PrivateKey.generate()
        x_priv = x25519.X25519PrivateKey.generate()
        save_keys_to_disk(ed_priv, x_priv)
    return ed_priv, ed_priv.public_key(), x_priv, x_priv.public_key()


# ------------ SÉRIALISATION ------------

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def deserialize_ed25519_public_key(data):
    return ed25519.Ed25519PublicKey.from_public_bytes(data)

def deserialize_x25519_public_key(data):
    return x25519.X25519PublicKey.from_public_bytes(data)


# ------------ CHIFFREMENT / DÉCHIFFREMENT ------------

def derive_shared_key(private_key: x25519.X25519PrivateKey, peer_public_key_bytes: bytes):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    shared_secret = private_key.exchange(peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    )
    return hkdf.derive(shared_secret)


def encrypt_message(message: str, peer_x25519_pub_bytes: bytes, sender_ed25519_priv: ed25519.Ed25519PrivateKey):
    ephemeral_priv = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()

    shared_key = derive_shared_key(ephemeral_priv, peer_x25519_pub_bytes)

    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    signature = sender_ed25519_priv.sign(ciphertext)

    return (
        ephemeral_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        + nonce
        + encryptor.tag
        + signature
        + ciphertext
    )


def decrypt_message(data: bytes, receiver_x25519_priv: x25519.X25519PrivateKey, sender_ed25519_pub: ed25519.Ed25519PublicKey):
    try:
        ephemeral_pub = data[:32]
        nonce = data[32:44]
        tag = data[44:60]
        signature = data[60:60 + 64]
        ciphertext = data[60 + 64:]

        shared_key = derive_shared_key(receiver_x25519_priv, ephemeral_pub)

        sender_ed25519_pub.verify(signature, ciphertext)  # throws if invalid

        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except InvalidSignature:
        return "[Message non vérifié !]"
    except Exception as e:
        return f"[Erreur de déchiffrement : {e}]"


# ------------ EMPREINTE (IDENTITÉ) ------------

def get_fingerprint(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()
