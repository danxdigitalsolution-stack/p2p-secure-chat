# P2P Secure Chat & File Transfer

End-to-end encrypted, peer-to-peer chat and file transfer application for Windows, macOS, and Linux, built with **PySide6**.

No central server ever sees your messages or files — two peers connect directly to each other over a TCP tunnel, and every byte on the wire is encrypted with a key only the two of you can derive.

---
<img width="569" height="517" alt="image" src="https://github.com/user-attachments/assets/e33a0896-b51d-478b-a1c3-824b994e37c9" />

---

## Features

- **Zero manual network setup** — a [pyngrok](https://github.com/alexdlaird/pyngrok) TCP tunnel is opened automatically, so there's no port forwarding or router configuration required to receive a connection.
- **Session ID + PIN pairing** — the host gets a public `host:port` Session ID and a random 6-character PIN to share with their partner (over any channel — voice call, another messenger, etc.).
- **AES-256-GCM authenticated encryption** — every chat message and every file chunk is individually encrypted and authenticated, giving confidentiality, integrity, and tamper detection on each frame.
- **PIN-derived session key** — the AES-256 key is derived from the shared PIN via PBKDF2-HMAC-SHA256 (390,000 iterations), so the key itself is never transmitted.
- **Handshake verification** — both sides confirm they derived the same key before the chat room opens; a wrong PIN fails immediately with a clear error instead of silently producing garbled data.
- **Streaming file transfer** — files are sent in 64 KB chunks, read directly from disk and written directly to disk on the other end, so arbitrarily large files can be transferred without loading them into RAM.
- **Chat UI** — text bubbles, inline image thumbnails with a click-to-view full-size popup, generic file bubbles for other file types, and a live progress bar during transfers.
- **Clean shutdown** — sockets are closed and the ngrok tunnel is killed on application exit, so nothing is left running in the background.

## Requirements

- Python 3.10+ (uses `tuple[bytes, bytes]`-style built-in generic type hints)
- Dependencies:

  ```bash
  pip install PySide6 pyngrok cryptography
  ```

## Usage

```bash
python p2p_secure_chat_v1.py
```

### Hosting a session (receiving a connection)

1. Open the **"Receive Session / Chat Room"** tab.
2. *(Optional)* Enter your ngrok auth token — recommended for a more stable/longer-lived tunnel; the app works without one but is subject to ngrok's anonymous tunnel limits.
3. Click **Start**. The app opens a tunnel and displays a **Session ID** (e.g. `0.tcp.ngrok.io:12345`) and a **PIN**.
4. Share the Session ID and PIN with your partner through any channel.
5. Wait for your partner to connect — once the PIN handshake succeeds, the chat window opens automatically.

### Connecting to a partner

1. Open the **"Connect to Partner"** tab.
2. Enter the **Session ID** and **PIN** your partner shared with you.
3. Click **Connect**. Once the handshake succeeds, the chat window opens automatically.

### In the chat room

- Type a message and press Enter / click Send.
- Click the attach/file button to send a file — progress is shown live on both sides.
- Received images render as inline thumbnails (click to view full size); other files appear as file bubbles you can open from disk.
- Incoming files are saved to `~/P2PSecureChat_Received/` (auto-created on first run). If a filename already exists, a numeric suffix is appended so nothing is overwritten.

## How It Works

### Encryption

Both peers independently derive the same 32-byte AES-256 key from the shared PIN using `PBKDF2HMAC(SHA256, iterations=390_000)` with a fixed, hard-coded salt. Every message or file chunk is then encrypted individually with `AES-256-GCM`, using a fresh random 12-byte nonce each time — this authenticates and protects each frame independently, and since a nonce is never reused with the same key, the fixed salt does not weaken confidentiality of the traffic itself. It does make offline brute-forcing of the PIN somewhat easier than a random per-session salt would, which is an accepted trade-off for a short-lived, ad-hoc P2P session — see the `CryptoManager` docstring in the source for the full rationale.

### Wire protocol

Since TCP is a raw byte stream with no built-in message boundaries, every frame is explicitly length-prefixed:

```
[1 byte main_type][1 byte sub_type][8 bytes payload_length (big-endian)]
[12 bytes nonce][payload_length − 12 bytes ciphertext]
```

- `main_type`: `TEXT` (1) or `FILE` (2)
- `sub_type` (files only): `META` (0, filename + size), `CHUNK` (1, one encrypted chunk), `END` (2, marks transfer completion)

### Handshake

Before the chat room opens, the connecting side sends an encrypted `MACAN_P2P_HELLO_V1` magic string; the host decrypts it (proving it derived the same key from the PIN) and replies with an encrypted `MACAN_P2P_ACK_V1`. If decryption fails or the magic string doesn't match, the connection is rejected with a "wrong PIN" error before any chat data is exchanged.

## Project Structure

Everything lives in a single file, `p2p_secure_chat_v1.py`:

| Section | Responsibility |
|---|---|
| `CryptoManager` | PBKDF2 key derivation + AES-256-GCM encrypt/decrypt |
| `build_frame` / `recv_frame` / `recv_exact` | Length-prefixed wire protocol |
| `HostSetupThread` | Opens the ngrok tunnel, listens for a connection, handles the receiving side of the handshake |
| `ClientSetupThread` | Connects to a partner's Session ID, handles the initiating side of the handshake |
| `ChatReceiveThread` | Long-running background reader — decrypts incoming frames and emits Qt signals for text/file events |
| `FileSendThread` | Streams a file to the peer in 64 KB chunks without loading it fully into memory |
| `HostTab` / `ConnectTab` | The two setup tabs in the main window |
| `ChatWindow` | The actual chat room UI (bubbles, thumbnails, progress bar) |
| `MainWindow` | Top-level window; owns tab switching and shutdown cleanup |

## Known Limitations

- **Fixed PBKDF2 salt** — see the encryption note above; a future hardening step would be exchanging a random salt during the handshake instead of using a hard-coded one.
- **One connection per host session** — the listening socket accepts a single incoming connection, matching the 1-to-1 chat model of this app.
- **Requires `pyngrok`** — if it isn't installed, the app shows a clear error dialog on startup pointing to `pip install pyngrok` rather than crashing.


