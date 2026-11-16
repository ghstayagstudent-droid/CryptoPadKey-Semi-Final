"""Cryptographic building blocks used by CryptoPad's educational demo.

The app uses ElGamal-style ephemeral key agreement to derive a shared secret,
HKDF-SHA256 to derive an AES key, and AES-256-GCM to protect note bytes.
This hand-built protocol is for learning only and has not been audited.
"""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from secrets import randbelow

# RFC 3526 group 14 (2048-bit MODP), with its published generator.
P = int("""FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA
8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966
D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF""".replace("\n", ""), 16)
G = 2
KEY_WRAP_AAD = b"CryptoPad-Wrapped-ElGamal-Key-v1"
KEY_WRAP_KDF = "scrypt-n32768-r8-p1"
PACKET_AAD = b"CryptoPad-ElGamal-v1"
HKDF_INFO = b"CryptoPad ElGamal hybrid demo v1"


def b64(value: bytes) -> str:
    """Encode binary packet fields as portable ASCII base64."""
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    """Decode a strict base64 field, returning a user-safe validation error."""
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Invalid base64 data.") from exc


def derive_wrap_key(master_key: str, salt: bytes) -> bytes:
    """Derive the AES key that protects a private key inside saved note files."""
    if not isinstance(master_key, str) or len(master_key) < 12:
        raise ValueError("Enter the master key (at least 12 characters).")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(master_key.encode("utf-8"))


def _derive_message_key(shared_secret: int, salt: bytes) -> bytes:
    """Turn the ElGamal shared integer into an AES key using domain-separated HKDF."""
    secret_bytes = shared_secret.to_bytes((P.bit_length() + 7) // 8, "big")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(secret_bytes)


def encrypt_message(text: str, recipient_public_key: int) -> dict:
    """Encrypt UTF-8 plaintext using a fresh ephemeral ElGamal exponent and AES-GCM."""
    ephemeral = randbelow(P - 3) + 2
    c1 = pow(G, ephemeral, P)
    shared_secret = pow(recipient_public_key, ephemeral, P)
    salt, nonce = os.urandom(16), os.urandom(12)
    message_key = _derive_message_key(shared_secret, salt)
    ciphertext = AESGCM(message_key).encrypt(nonce, text.encode("utf-8"), PACKET_AAD)
    return {
        "version": 1,
        "algorithm": "ElGamal-2048 + HKDF-SHA256 + AES-256-GCM",
        "c1": format(c1, "x"),
        "salt": b64(salt),
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
        "aad": b64(PACKET_AAD),
    }


def decrypt_packet(packet: dict, private_key: int) -> str:
    """Validate, authenticate, and decode a packet with its matching private key.

    AES-GCM verifies the ciphertext and associated metadata before plaintext is
    returned; any tampering raises an exception and must not be treated as text.
    """
    if not isinstance(packet, dict) or packet.get("version") != 1:
        raise ValueError("Unsupported or invalid encrypted packet.")
    try:
        c1 = int(packet["c1"], 16)
        salt, nonce = unb64(packet["salt"]), unb64(packet["nonce"])
        aad, ciphertext = unb64(packet["aad"]), unb64(packet["ciphertext"])
    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid encrypted packet fields.") from exc
    if not 1 < c1 < P - 1:
        raise ValueError("Invalid ElGamal component.")
    if len(nonce) != 12 or len(salt) != 16 or aad != PACKET_AAD:
        raise ValueError("Invalid packet metadata.")

    # c1^x recreates y^k, so the receiver derives the same AES key as the sender.
    shared_secret = pow(c1, private_key, P)
    message_key = _derive_message_key(shared_secret, salt)
    return AESGCM(message_key).decrypt(nonce, ciphertext, aad).decode("utf-8")
