"use strict";

// Small same-origin API wrapper shared by the landing page and workspace.
async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok || data.ok === false) throw new Error(data.error || "Request failed.");
  return data;
}

function showStatus(message, bad = false) {
  const status = document.getElementById("status");
  if (!status) return;
  status.textContent = message;
  status.dataset.state = bad ? "error" : "success";
}

function showDecryptDialog(message, title = "Decrypted message") {
  const dialog = document.getElementById("decrypt-dialog");
  const output = document.getElementById("decrypted-message");
  if (!dialog || !output) return;
  document.getElementById("decrypt-dialog-title").textContent = title;
  output.textContent = message;
  if (!dialog.open) dialog.showModal();
}

// Read only small text documents; binary/oversized files do not belong in a note editor.
async function readTextFile(file) {
  const maxSize = 5 * 1024 * 1024;
  if (!file) return "";
  if (file.size > maxSize) throw new Error("Choose a text file smaller than 5 MB.");
  const text = await file.text();
  if (text.includes("\u0000")) throw new Error("That file does not look like a text document.");
  return text;
}

// Shared file drop behavior: prevent the browser from navigating to the dropped file,
// provide a visible drag state, and pass the first selected text file to the page.
function enableTextFileDrop(surface, dropzone, onText) {
  if (!surface) return;
  const setDragging = (active) => dropzone?.classList.toggle("is-dragging", active);
  surface.addEventListener("dragenter", (event) => {
    event.preventDefault();
    setDragging(true);
  });
  surface.addEventListener("dragover", (event) => event.preventDefault());
  surface.addEventListener("dragleave", (event) => {
    if (!surface.contains(event.relatedTarget)) setDragging(false);
  });
  surface.addEventListener("drop", async (event) => {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;
    try {
      await onText(await readTextFile(file), file);
    } catch (error) {
      showStatus(error.message, true);
    }
  });
}

// Build a fresh session keypair and present only its public portion in the UI.
async function generateKey(masterKey) {
  const data = await api("/api/session", { master_key: masterKey });
  const status = document.getElementById("key-status");
  if (status) status.innerHTML = `<i></i> Active · ${data.key_bits}-bit ElGamal key`;
  const output = document.getElementById("public-key-output");
  if (output) output.value = `p = ${data.public_key.p}\ng = ${data.public_key.g}\ny = ${data.public_key.y}`;
  showStatus("New temporary keypair generated.");
}

function bindDialog() {
  const dialog = document.getElementById("decrypt-dialog");
  if (!dialog) return;
  document.getElementById("close-decrypt-dialog").addEventListener("click", () => dialog.close());
  document.getElementById("decrypt-dialog-done").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
}

function bindLandingPage() {
  const startForm = document.querySelector("#home form.form-stack");
  startForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const first = document.getElementById("master-passphrase").value;
    const confirmation = document.getElementById("confirm-passphrase").value;
    if (first !== confirmation) {
      alert("The passphrases do not match.");
      return;
    }
    try {
      await generateKey(first);
      location.href = "workspace.html";
    } catch (error) {
      alert(error.message);
    }
  });

  const decryptForm = document.getElementById("decrypt-form");
  if (!decryptForm) return;
  const packetField = document.getElementById("encrypted-packet");
  const fileInput = document.getElementById("landing-file-input");
  const loadFile = async (text, file) => {
    packetField.value = text;
    packetField.dispatchEvent(new Event("input", { bubbles: true }));
    const help = document.getElementById("landing-file-help");
    if (help) help.textContent = `Loaded ${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
  };
  enableTextFileDrop(document.getElementById("home"), document.getElementById("landing-dropzone"), loadFile);
  fileInput?.addEventListener("change", async () => {
    try {
      const file = fileInput.files?.[0];
      if (file) await loadFile(await readTextFile(file), file);
    } catch (error) {
      const help = document.getElementById("landing-file-help");
      if (help) help.textContent = error.message;
    } finally {
      fileInput.value = "";
    }
  });
  document.getElementById("landing-dropzone")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      fileInput?.click();
    }
  });

  decryptForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const saved = packetField.value.trim();
      const result = saved.startsWith("CRYPTOPAD-ENCRYPTED-NOTE-V1")
        ? await api("/api/decrypt-saved", {
          file_text: saved,
          master_key: document.getElementById("existing-master-key").value,
        })
        : await api("/api/decrypt", { packet: JSON.parse(saved) });
      showDecryptDialog(result.text);
    } catch (error) {
      showDecryptDialog(error.message, "Could not decrypt");
    }
  });
}

function bindWorkspace() {
  const editor = document.getElementById("note-content");
  if (!editor) return;
  const count = document.getElementById("word-count");
  const updateCount = () => {
    const text = editor.value.trim();
    count.textContent = `Words: ${text ? text.split(/\s+/).length : 0} · Chars: ${editor.value.length}`;
  };
  editor.addEventListener("input", updateCount);

  const editorCard = document.querySelector(".editor-card");
  const importText = async (text, file) => {
    editor.value = text;
    document.getElementById("note-title").value = file.name.replace(/\.txt$/i, "");
    updateCount();
    showStatus(`Loaded ${file.name}. Review it, then encrypt the message.`);
  };
  enableTextFileDrop(editorCard, editorCard, importText);
  document.getElementById("plaintext-file-input")?.addEventListener("change", async (event) => {
    const input = event.currentTarget;
    try {
      const file = input.files?.[0];
      if (file) await importText(await readTextFile(file), file);
    } catch (error) {
      showStatus(error.message, true);
    } finally {
      input.value = "";
    }
  });

  api("/api/key").then((data) => {
    document.getElementById("key-status").innerHTML = `<i></i> Active · ${data.key_bits}-bit ElGamal key`;
    document.getElementById("public-key-output").value = `p = ${data.public_key.p}\ng = ${data.public_key.g}\ny = ${data.public_key.y}`;
  }).catch(() => {
    document.getElementById("key-status").textContent = "No key loaded";
  });

  document.getElementById("generate-key").addEventListener("click", () => {
    generateKey(document.getElementById("master-key").value).catch((error) => showStatus(error.message, true));
  });
  document.getElementById("encrypt-button").addEventListener("click", async () => {
    try {
      if (!editor.value.trim()) throw new Error("Write or open a text message first.");
      const result = await api("/api/encrypt", { text: editor.value });
      document.getElementById("packet-output").value = JSON.stringify(result.packet, null, 2);
      showStatus("Message encrypted successfully.");
    } catch (error) {
      showStatus(error.message, true);
    }
  });
  document.getElementById("clear-button").addEventListener("click", () => {
    editor.value = "";
    document.getElementById("packet-output").value = "";
    updateCount();
    showStatus("Editor cleared.");
  });
  document.getElementById("copy-packet").addEventListener("click", () => {
    navigator.clipboard.writeText(document.getElementById("packet-output").value)
      .then(() => showStatus("Packet copied."))
      .catch(() => showStatus("Clipboard unavailable.", true));
  });
  document.getElementById("copy-key").addEventListener("click", () => {
    navigator.clipboard.writeText(document.getElementById("public-key-output").value)
      .then(() => showStatus("Public key copied."))
      .catch(() => showStatus("Clipboard unavailable.", true));
  });
  document.getElementById("save-packet").addEventListener("click", async () => {
    try {
      const packet = JSON.parse(document.getElementById("packet-output").value);
      if (packet.version !== 1 || typeof packet.ciphertext !== "string") {
        throw new Error("Encrypt a message before saving.");
      }
      const result = await api("/api/export", { packet });
      const url = URL.createObjectURL(new Blob([result.file_text], { type: "text/plain;charset=utf-8" }));
      const title = document.getElementById("note-title").value.trim();
      const safeTitle = title.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${safeTitle || "cryptopad-encrypted"}.txt`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showStatus("Encrypted note saved as a .txt file.");
    } catch (error) {
      showStatus(error instanceof SyntaxError ? "Encrypt a message before saving." : error.message, true);
    }
  });
  document.getElementById("lock-button").addEventListener("click", async () => {
    try {
      await api("/api/lock", {});
    } finally {
      location.href = "index.html";
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  bindDialog();
  bindLandingPage();
  bindWorkspace();
});
