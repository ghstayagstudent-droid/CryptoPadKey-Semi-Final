"""Flask routes and in-memory session management for CryptoPad."""
from flask import Flask, request, jsonify, session, send_file, send_from_directory
from secrets import randbelow, token_urlsafe
from pathlib import Path
import json
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
except ImportError:
    AESGCM = None

from crypto_utils import (
    G, KEY_WRAP_AAD, KEY_WRAP_KDF, P, b64, decrypt_packet,
    derive_wrap_key, encrypt_message, unb64,
)


def require_aesgcm():
    if AESGCM is None:
        raise RuntimeError("The 'cryptography' package is required to run CryptoPad. Install it with 'pip install cryptography'.")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
app.secret_key = os.environ.get("CRYPTOPAD_SECRET", token_urlsafe(48))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
# Volatile process memory only. Restarting server clears all keys.
KEYS = {}

def current_key():
    kid = session.get("kid")
    if not kid or kid not in KEYS: raise ValueError("No active keypair. Generate a keypair first.")
    return KEYS[kid]

# Page routes keep the static frontend on the same origin as the JSON API.
@app.get("/")
def home(): return send_file(FRONTEND_DIR / "index.html")

@app.get("/workspace.html")
def workspace(): return send_file(FRONTEND_DIR / "workspace.html")

@app.get("/app.js")
def frontend_javascript(): return send_file(FRONTEND_DIR / "app.js", mimetype="application/javascript")

@app.get("/styles.css")
def frontend_stylesheet(): return send_file(FRONTEND_DIR / "styles.css", mimetype="text/css")

@app.post("/api/session")
def create_session():
    data = request.get_json(force=True) or {}
    master_key = data.get("master_key")
    if not isinstance(master_key, str) or len(master_key) < 12:
        return jsonify(ok=False, error="Choose a master key with at least 12 characters."), 400
    x = randbelow(P - 3) + 2
    y = pow(G, x, P)
    key_salt = os.urandom(16); key_nonce = os.urandom(12)
    wrapping_key = derive_wrap_key(master_key, key_salt)
    wrapped_private_key = AESGCM(wrapping_key).encrypt(
        key_nonce, x.to_bytes((P.bit_length()+7)//8, "big"), KEY_WRAP_AAD)
    kid = token_urlsafe(24)
    KEYS[kid] = {"x": x, "y": y, "key_salt": key_salt,
                 "key_nonce": key_nonce, "wrapped_private_key": wrapped_private_key}
    session["kid"] = kid
    return jsonify(ok=True, public_key={"p": format(P,"x"), "g": format(G,"x"), "y": format(y,"x")},
                   key_bits=P.bit_length())

@app.get("/api/key")
def get_key():
    key=current_key()
    return jsonify(public_key={"p":format(P,"x"),"g":format(G,"x"),"y":format(key["y"],"x")},
                   key_bits=P.bit_length())

@app.post("/api/encrypt")
def encrypt():
    try:
        data=request.get_json(force=True)
        text=data.get("text","")
        if not isinstance(text,str) or not text: raise ValueError("Enter some text to encrypt.")
        key=current_key()
        raw=text.encode("utf-8")
        # Crypto primitives live in crypto_utils; this route only validates input and serializes output.
        packet = encrypt_message(text, key["y"])
        return jsonify(ok=True, packet=packet)
    except ValueError as e: return jsonify(ok=False,error=str(e)),400
    except Exception: return jsonify(ok=False,error="Encryption failed."),400

@app.post("/api/decrypt")
def decrypt():
    try:
        packet=request.get_json(force=True).get("packet")
        key=current_key()
        plaintext=decrypt_packet(packet, key["x"])
        return jsonify(ok=True,text=plaintext)
    except Exception: return jsonify(ok=False,error="Decryption failed. Check the packet and make sure this session has the matching private key."),400

@app.post("/api/export")
def export_encrypted_note():
    try:
        data = request.get_json(force=True) or {}
        packet = data.get("packet")
        key = current_key()
        if not isinstance(packet, dict) or packet.get("version") != 1:
            raise ValueError("Encrypt a message before saving.")
        note = {
            "packet": b64(json.dumps(packet, separators=(",", ":")).encode("utf-8")),
            "kdf": KEY_WRAP_KDF,
            "key_salt": b64(key["key_salt"]),
            "key_nonce": b64(key["key_nonce"]),
            "wrapped_private_key": b64(key["wrapped_private_key"]),
            "public_key_y": format(key["y"], "x"),
        }
        file_text = "CRYPTOPAD-ENCRYPTED-NOTE-V1\n" + "".join(f"{k}={v}\n" for k, v in note.items())
        return jsonify(ok=True, file_text=file_text)
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400
    except Exception:
        return jsonify(ok=False, error="Could not save encrypted note."), 400

@app.post("/api/decrypt-saved")
def decrypt_saved_note():
    try:
        data = request.get_json(force=True) or {}
        file_text = data.get("file_text")
        if not isinstance(file_text, str):
            raise ValueError("Paste an encrypted CryptoPad text file.")
        lines = file_text.splitlines()
        if not lines or lines[0].strip() != "CRYPTOPAD-ENCRYPTED-NOTE-V1":
            raise ValueError("This is not a supported CryptoPad encrypted text file.")
        fields = {}
        for line in lines[1:]:
            if not line:
                continue
            name, sep, value = line.partition("=")
            if not sep or name in fields:
                raise ValueError("Invalid encrypted note file.")
            fields[name] = value
        required = {"packet", "kdf", "key_salt", "key_nonce", "wrapped_private_key", "public_key_y"}
        if set(fields) != required or fields["kdf"] != KEY_WRAP_KDF:
            raise ValueError("Unsupported or invalid encrypted note file.")
        packet = json.loads(unb64(fields["packet"]).decode("utf-8"))
        key_salt = unb64(fields["key_salt"]); key_nonce = unb64(fields["key_nonce"])
        wrapped = unb64(fields["wrapped_private_key"])
        if len(key_salt) != 16 or len(key_nonce) != 12:
            raise ValueError("Invalid master-key metadata.")
        wrapping_key = derive_wrap_key(data.get("master_key"), key_salt)
        private_bytes = AESGCM(wrapping_key).decrypt(key_nonce, wrapped, KEY_WRAP_AAD)
        x = int.from_bytes(private_bytes, "big")
        y = int(fields["public_key_y"], 16)
        if not 1 < x < P - 1 or pow(G, x, P) != y:
            raise ValueError("Master key does not match this encrypted note.")
        plaintext = decrypt_packet(packet, x)
        return jsonify(ok=True, text=plaintext)
    except Exception:
        return jsonify(ok=False, error="Could not decrypt. Check the master key and encrypted text file."), 400

@app.post("/api/lock")
def lock():
    kid=session.pop("kid",None)
    if kid: KEYS.pop(kid,None)
    session.clear()
    return jsonify(ok=True)

@app.get("/health")
def health(): return jsonify(ok=True, service="CryptoPad educational ElGamal backend")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="127.0.0.1", port=port, debug=False)
