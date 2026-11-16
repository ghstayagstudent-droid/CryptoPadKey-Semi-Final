# CryptoPad — ElGamal educational encryption demo

## Run locally

Requires Python 3.10+.

```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:8080 (or http://localhost:8080). Do not open the HTML files directly; the Flask API must be running. Set the `PORT` environment variable before starting the app to use a different port.

## Quick user guide

1. Open the app and create a master key with at least 12 characters. Remember it: saved notes cannot be decrypted without it.
2. In the workspace, type a note or use **Open text file** to choose a `.txt` file. You can also drop a text file onto the editor.
3. Choose **Encrypt message**, then **Save as .txt** to download a CryptoPad encrypted note.
4. To open a saved note later, use the landing page file picker or drop the `.txt` note onto the drop area. Enter its master key and choose **Decrypt Message**. The workspace can also decrypt JSON packets from the matching active session.

The in-app **User guide** has the same workflow. File imports are text-only and limited to 5 MB.

## Code layout

- `backend/app.py` serves the pages and handles HTTP/session requests.
- `backend/crypto_utils.py` contains packet encryption/decryption, key derivation, and base64 helpers.
- `frontend/index.html` is the landing page and saved-note decrypt form.
- `frontend/workspace.html` is the text editor and encryption workspace.
- `frontend/app.js` contains the same-origin API client, page interactions, and file import/drop behavior.
- `frontend/styles.css` contains shared responsive styling.

## What works

- Creates a temporary ElGamal public/private keypair.
- Encrypts plaintext using ElGamal ephemeral key agreement, HKDF-SHA256 and AES-256-GCM.
- Saves notes as readable `.txt` containers holding encrypted content and a master-key-protected private key.
- Decrypts saved note files with the master key, including after the server restarts.
- Copies the public key / packet and saves the encrypted note as a `.txt` file.
- Locking the workspace clears the active key from process memory.

## Important security limitations

This is an educational prototype, not a production secure-notes product. The ElGamal group arithmetic is implemented in this application using Python big integers; the symmetric authenticated encryption, HKDF, and Scrypt key wrapping use the `cryptography` package. It has not had a security audit. The active private key is held in process memory for the current session; each saved `.txt` file also contains a copy wrapped with the master key. Anyone with the file can attempt offline guesses against that master key, so choose a strong, unique key and keep it safe. If it is lost, the file cannot be decrypted. Do not enter passwords, personal data, or other sensitive information. Use a standardized, reviewed hybrid-encryption protocol and vetted key management for real applications.

The backend binds to 127.0.0.1 by default and has debug mode disabled.
