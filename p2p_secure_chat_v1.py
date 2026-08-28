#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P2P Secure Chat & File Transfer
================================
End-to-end encrypted, peer-to-peer chat and file
transfer application for Windows / macOS / Linux, built with PySide6.

Key features
------------
- NAT traversal via an automatic pyngrok TCP tunnel (no manual port
  forwarding / router configuration required).
- Session ID + random 6-character PIN identification.
- AES-256-GCM authenticated encryption for every chat message and every
  file chunk (confidentiality + integrity + tamper detection).
- Chunked (64 KB) disk-to-socket / socket-to-disk file streaming so
  arbitrarily large files can be sent without loading them into RAM.
- WhatsApp-style chat room: text bubbles, image thumbnails with a
  full-size click-to-view popup, generic file bubbles, and a live
  progress bar during transfers.
- Clean shutdown: sockets are closed and the ngrok tunnel is killed on
  application exit, so nothing is left dangling in the background.

Dependencies
------------
    pip install PySide6 pyngrok cryptography

Run
---
    python p2p_secure_chat_v1.py
    
Dev: Danx Exodus - Macan Angkasa
https://github.com/danx123
"""

import sys
import os
import socket
import struct
import json
import secrets
import string
import traceback
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QPixmap, QIcon, QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget, QScrollArea, QFrame,
    QFileDialog, QMessageBox, QProgressBar, QDialog, QSizePolicy,
    QSpacerItem, QTextEdit
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

try:
    from pyngrok import ngrok
except ImportError:
    ngrok = None  # Handled gracefully at runtime with a clear error message.


# ============================================================================
# CONSTANTS
# ============================================================================

LOCAL_PORT = 12345
CHUNK_SIZE = 64 * 1024  # 64 KB, as required: never load whole files into RAM

# Main packet types (byte 1 of the frame header)
TYPE_TEXT = 1
TYPE_FILE = 2

# Sub-types used only when TYPE_FILE is set (byte 2 of the frame header)
SUB_META = 0   # File metadata (filename, filesize) - sent once before chunks
SUB_CHUNK = 1  # One encrypted 64 KB (or smaller, for the last block) chunk
SUB_END = 2    # Marks the end of a file transfer

# Handshake magic strings, used to verify both sides derived the same
# encryption key from the PIN before opening the chat room.
MAGIC_HELLO = "MACAN_P2P_HELLO_V1"
MAGIC_ACK = "MACAN_P2P_ACK_V1"

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}

DOWNLOADS_DIR = os.path.join(os.path.expanduser("~"), "P2PSecureChat_Received")
os.makedirs(DOWNLOADS_DIR, exist_ok=True)


# ============================================================================
# CRYPTOGRAPHY
# ============================================================================

class CryptoManager:
    """
    Derives a 32-byte AES-256 key from the session PIN using PBKDF2-HMAC-SHA256,
    then performs authenticated encryption/decryption with AES-GCM.

    NOTE ON THE STATIC SALT: per the spec this uses a fixed, hard-coded salt.
    Combined with a fresh random 12-byte nonce on every single message/chunk,
    this still prevents nonce reuse and keeps each session's traffic opaque
    to eavesdroppers. It is, however, weaker against offline PIN
    brute-forcing than a random per-session salt would be. For an ad-hoc,
    short-lived P2P session this is an acceptable trade-off; if you want to
    harden it further later, exchange a random salt during the handshake
    instead of hard-coding one.
    """

    STATIC_SALT = b"macan-p2p-static-salt-v1-fixed"
    PBKDF2_ITERATIONS = 390_000
    KEY_LENGTH = 32  # 256-bit key for AES-256-GCM
    NONCE_LENGTH = 12  # Recommended nonce size for AES-GCM

    def __init__(self, pin: str):
        self._key = self._derive_key(pin)
        self._aesgcm = AESGCM(self._key)

    def _derive_key(self, pin: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=self.STATIC_SALT,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(pin.encode("utf-8"))

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """Returns (nonce, ciphertext_with_auth_tag)."""
        nonce = os.urandom(self.NONCE_LENGTH)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> bytes:
        """Raises cryptography.exceptions.InvalidTag if the data was
        tampered with or the wrong PIN/key was used."""
        return self._aesgcm.decrypt(nonce, ciphertext, None)


# ============================================================================
# WIRE PROTOCOL (length-prefixed framing over a raw TCP stream)
# ============================================================================
#
# Frame layout:
#   [1 byte  main_type][1 byte sub_type][8 bytes payload_length (big-endian)]
#   [12 bytes nonce][payload_length-12 bytes ciphertext]
#
# TCP is a byte stream with no built-in message boundaries, so every frame
# is explicitly length-prefixed to let the receiver know exactly how many
# bytes to read for that message/chunk.

FRAME_HEADER_FORMAT = ">BBQ"
FRAME_HEADER_SIZE = struct.calcsize(FRAME_HEADER_FORMAT)


def build_frame(main_type: int, sub_type: int, nonce: bytes, ciphertext: bytes) -> bytes:
    payload = nonce + ciphertext
    header = struct.pack(FRAME_HEADER_FORMAT, main_type, sub_type, len(payload))
    return header + payload


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Reads exactly num_bytes from the socket or raises ConnectionError."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer.")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket):
    """Reads one full frame and returns (main_type, sub_type, nonce, ciphertext)."""
    header = recv_exact(sock, FRAME_HEADER_SIZE)
    main_type, sub_type, payload_len = struct.unpack(FRAME_HEADER_FORMAT, header)
    payload = recv_exact(sock, payload_len)
    nonce, ciphertext = payload[:12], payload[12:]
    return main_type, sub_type, nonce, ciphertext


def send_text_frame(sock: socket.socket, crypto: CryptoManager, text: str):
    nonce, ciphertext = crypto.encrypt(text.encode("utf-8"))
    sock.sendall(build_frame(TYPE_TEXT, 0, nonce, ciphertext))


def human_readable_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def random_pin(length: int = 6) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ============================================================================
# BACKGROUND THREADS
# ============================================================================

class HostSetupThread(QThread):
    """Opens the ngrok tunnel, generates the session ID/PIN, listens for a
    single incoming connection, and performs the receiving side of the
    PIN handshake."""

    session_ready = Signal(str, str)      # session_id, pin
    waiting_for_client = Signal()
    handshake_failed = Signal(str)
    connected = Signal(object, object)    # socket, CryptoManager
    error_occurred = Signal(str)

    def __init__(self, ngrok_authtoken: str = ""):
        super().__init__()
        self.ngrok_authtoken = ngrok_authtoken.strip()
        self._server_sock = None
        self._tunnel = None

    def run(self):
        try:
            if ngrok is None:
                raise RuntimeError(
                    "pyngrok is not installed. Run: pip install pyngrok"
                )

            if self.ngrok_authtoken:
                ngrok.set_auth_token(self.ngrok_authtoken)

            self._tunnel = ngrok.connect(LOCAL_PORT, "tcp")
            # tunnel.public_url looks like "tcp://0.tcp.ngrok.io:12345"
            session_id = self._tunnel.public_url.replace("tcp://", "")
            pin = random_pin()

            self.session_ready.emit(session_id, pin)
            self.waiting_for_client.emit()

            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(("0.0.0.0", LOCAL_PORT))
            self._server_sock.listen(1)

            conn, addr = self._server_sock.accept()

            crypto = CryptoManager(pin)

            # --- Handshake (receiving side) ---
            main_type, sub_type, nonce, ciphertext = recv_frame(conn)
            try:
                plaintext = crypto.decrypt(nonce, ciphertext).decode("utf-8")
            except Exception:
                self.handshake_failed.emit(
                    "The connecting partner entered the wrong PIN."
                )
                conn.close()
                return

            if main_type != TYPE_TEXT or plaintext != MAGIC_HELLO:
                self.handshake_failed.emit(
                    "Handshake verification failed (unexpected data)."
                )
                conn.close()
                return

            send_text_frame(conn, crypto, MAGIC_ACK)
            self.connected.emit(conn, crypto)

        except Exception as exc:
            self.error_occurred.emit(str(exc))

    def cleanup(self):
        """Best-effort cleanup of the listening socket and ngrok tunnel."""
        try:
            if self._server_sock:
                self._server_sock.close()
        except Exception:
            pass
        try:
            if self._tunnel:
                ngrok.disconnect(self._tunnel.public_url)
        except Exception:
            pass
        try:
            if ngrok is not None:
                ngrok.kill()
        except Exception:
            pass


class ClientSetupThread(QThread):
    """Connects to a partner's ngrok session ID and performs the initiating
    side of the PIN handshake."""

    connected = Signal(object, object)   # socket, CryptoManager
    handshake_failed = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, session_id: str, pin: str):
        super().__init__()
        self.session_id = session_id.strip()
        self.pin = pin.strip()
        self._sock = None

    def run(self):
        try:
            if ":" not in self.session_id:
                raise ValueError(
                    "Invalid Session ID format. Expected host:port, "
                    "e.g. 0.tcp.ngrok.io:12345"
                )
            host, port_str = self.session_id.rsplit(":", 1)
            port = int(port_str)

            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(15)
            self._sock.connect((host, port))
            self._sock.settimeout(None)

            crypto = CryptoManager(self.pin)

            # --- Handshake (connecting side) ---
            send_text_frame(self._sock, crypto, MAGIC_HELLO)
            main_type, sub_type, nonce, ciphertext = recv_frame(self._sock)
            try:
                plaintext = crypto.decrypt(nonce, ciphertext).decode("utf-8")
            except Exception:
                self.handshake_failed.emit(
                    "Incorrect PIN, or the Session ID belongs to a different session."
                )
                self._sock.close()
                return

            if main_type != TYPE_TEXT or plaintext != MAGIC_ACK:
                self.handshake_failed.emit("Handshake verification failed.")
                self._sock.close()
                return

            self.connected.emit(self._sock, crypto)

        except Exception as exc:
            self.error_occurred.emit(str(exc))


class ChatReceiveThread(QThread):
    """Runs for the lifetime of an established chat session, continuously
    reading frames off the socket and emitting Qt signals for the GUI."""

    text_received = Signal(str)
    file_incoming = Signal(str, int)          # filename, filesize
    file_progress = Signal(int)               # percent (0-100)
    file_received = Signal(str, str, int)     # filename, local_path, filesize
    connection_lost = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, sock: socket.socket, crypto: CryptoManager):
        super().__init__()
        self.sock = sock
        self.crypto = crypto
        self._running = True

        self._incoming_file = None
        self._incoming_filename = ""
        self._incoming_path = ""
        self._incoming_size = 0
        self._incoming_received = 0

    def stop(self):
        self._running = False

    def run(self):
        while self._running:
            try:
                main_type, sub_type, nonce, ciphertext = recv_frame(self.sock)
            except (ConnectionError, OSError):
                if self._running:
                    self.connection_lost.emit("The connection to your partner was lost.")
                break
            except Exception as exc:
                if self._running:
                    self.error_occurred.emit(f"Network error: {exc}")
                break

            try:
                plaintext = self.crypto.decrypt(nonce, ciphertext)
            except Exception:
                self.error_occurred.emit(
                    "Security error: received data failed decryption "
                    "(possible tampering or key mismatch)."
                )
                continue

            try:
                if main_type == TYPE_TEXT:
                    self.text_received.emit(plaintext.decode("utf-8"))

                elif main_type == TYPE_FILE:
                    if sub_type == SUB_META:
                        meta = json.loads(plaintext.decode("utf-8"))
                        self._incoming_filename = os.path.basename(meta["filename"])
                        self._incoming_size = int(meta["filesize"])
                        self._incoming_received = 0
                        self._incoming_path = self._unique_download_path(
                            self._incoming_filename
                        )
                        self._incoming_file = open(self._incoming_path, "wb")
                        self.file_incoming.emit(
                            self._incoming_filename, self._incoming_size
                        )

                    elif sub_type == SUB_CHUNK:
                        if self._incoming_file:
                            self._incoming_file.write(plaintext)
                            self._incoming_received += len(plaintext)
                            if self._incoming_size > 0:
                                percent = int(
                                    self._incoming_received / self._incoming_size * 100
                                )
                            else:
                                percent = 100
                            self.file_progress.emit(min(percent, 100))

                    elif sub_type == SUB_END:
                        if self._incoming_file:
                            self._incoming_file.close()
                            self.file_received.emit(
                                self._incoming_filename,
                                self._incoming_path,
                                self._incoming_size,
                            )
                        self._incoming_file = None

            except Exception as exc:
                self.error_occurred.emit(f"Error processing incoming data: {exc}")

    @staticmethod
    def _unique_download_path(filename: str) -> str:
        base, ext = os.path.splitext(filename)
        candidate = os.path.join(DOWNLOADS_DIR, filename)
        counter = 1
        while os.path.exists(candidate):
            candidate = os.path.join(DOWNLOADS_DIR, f"{base}_{counter}{ext}")
            counter += 1
        return candidate


class FileSendThread(QThread):
    """Streams a file to the peer in 64 KB chunks, read directly from disk,
    so large files never need to be fully loaded into memory."""

    progress_updated = Signal(int)
    send_finished = Signal(str, str, int)   # filename, filepath, filesize
    error_occurred = Signal(str)

    def __init__(self, sock: socket.socket, crypto: CryptoManager, filepath: str):
        super().__init__()
        self.sock = sock
        self.crypto = crypto
        self.filepath = filepath

    def run(self):
        try:
            filename = os.path.basename(self.filepath)
            filesize = os.path.getsize(self.filepath)

            meta = json.dumps({"filename": filename, "filesize": filesize}).encode("utf-8")
            nonce, ciphertext = self.crypto.encrypt(meta)
            self.sock.sendall(build_frame(TYPE_FILE, SUB_META, nonce, ciphertext))

            sent = 0
            with open(self.filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    nonce, ciphertext = self.crypto.encrypt(chunk)
                    self.sock.sendall(build_frame(TYPE_FILE, SUB_CHUNK, nonce, ciphertext))
                    sent += len(chunk)
                    percent = int(sent / filesize * 100) if filesize > 0 else 100
                    self.progress_updated.emit(min(percent, 100))

            nonce, ciphertext = self.crypto.encrypt(b"{}")
            self.sock.sendall(build_frame(TYPE_FILE, SUB_END, nonce, ciphertext))

            self.send_finished.emit(filename, self.filepath, filesize)

        except Exception as exc:
            self.error_occurred.emit(f"Failed to send file: {exc}")


# ============================================================================
# CHAT UI WIDGETS
# ============================================================================

class ClickableImageLabel(QLabel):
    """A QLabel that shows a small thumbnail and opens a full-size viewer
    popup when clicked."""

    def __init__(self, full_pixmap: QPixmap, parent=None):
        super().__init__(parent)
        self._full_pixmap = full_pixmap
        thumb = full_pixmap.scaled(
            150, 150, Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        self.setPixmap(thumb)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("Click to view full size")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            viewer = ImageViewerDialog(self._full_pixmap, self.window())
            viewer.exec()
        super().mousePressEvent(event)


class ImageViewerDialog(QDialog):
    """Full-size image popup, closable via a button."""

    def __init__(self, pixmap: QPixmap, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Image Viewer")
        self.resize(
            min(pixmap.width() + 40, 1000), min(pixmap.height() + 90, 800)
        )

        layout = QVBoxLayout(self)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        image_label = QLabel()
        image_label.setAlignment(Qt.AlignCenter)
        image_label.setPixmap(pixmap)
        scroll.setWidget(image_label)
        layout.addWidget(scroll)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)


class ChatBubble(QFrame):
    """Base bubble frame with WhatsApp-style alignment and coloring."""

    def __init__(self, is_own: bool, parent=None):
        super().__init__(parent)
        self.is_own = is_own
        bg_color = "#DCF8C6" if is_own else "#FFFFFF"
        self.setStyleSheet(
            f"""
            QFrame#bubble {{
                background-color: {bg_color};
                border: 1px solid #D9D9D9;
                border-radius: 10px;
            }}
            """
        )
        self.setObjectName("bubble")
        self.setMaximumWidth(360)


class TextChatBubble(ChatBubble):
    def __init__(self, sender_name: str, text: str, is_own: bool, parent=None):
        super().__init__(is_own, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)

        sender_label = QLabel(sender_name)
        sender_label.setStyleSheet("color:#555; font-weight:bold; font-size:11px;")
        layout.addWidget(sender_label)

        text_label = QLabel(text)
        text_label.setWordWrap(True)
        layout.addWidget(text_label)

        time_label = QLabel(datetime.now().strftime("%H:%M"))
        time_label.setStyleSheet("color:#999; font-size:9px;")
        time_label.setAlignment(Qt.AlignRight)
        layout.addWidget(time_label)


class ImageChatBubble(ChatBubble):
    def __init__(self, sender_name: str, filename: str, pixmap: QPixmap,
                 is_own: bool, parent=None):
        super().__init__(is_own, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)

        sender_label = QLabel(sender_name)
        sender_label.setStyleSheet("color:#555; font-weight:bold; font-size:11px;")
        layout.addWidget(sender_label)

        image_label = ClickableImageLabel(pixmap)
        layout.addWidget(image_label, alignment=Qt.AlignCenter)

        name_label = QLabel(filename)
        name_label.setStyleSheet("color:#666; font-size:10px;")
        name_label.setWordWrap(True)
        layout.addWidget(name_label)


class FileChatBubble(ChatBubble):
    def __init__(self, sender_name: str, filename: str, filesize: int,
                 is_own: bool, parent=None):
        super().__init__(is_own, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)

        sender_label = QLabel(sender_name)
        sender_label.setStyleSheet("color:#555; font-weight:bold; font-size:11px;")
        layout.addWidget(sender_label)

        row = QHBoxLayout()
        icon_label = QLabel("\U0001F4C4")  # 📄
        icon_label.setStyleSheet("font-size:28px;")
        row.addWidget(icon_label)

        info_layout = QVBoxLayout()
        name_label = QLabel(filename)
        name_label.setWordWrap(True)
        name_label.setStyleSheet("font-weight:bold;")
        size_label = QLabel(human_readable_size(filesize))
        size_label.setStyleSheet("color:#777; font-size:10px;")
        info_layout.addWidget(name_label)
        info_layout.addWidget(size_label)

        row.addLayout(info_layout)
        layout.addLayout(row)


class ProgressChatBubble(ChatBubble):
    """Live progress bar shown while a file transfer is in flight."""

    def __init__(self, sender_name: str, filename: str, is_own: bool, parent=None):
        super().__init__(is_own, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)

        label_text = f"{'Sending' if is_own else 'Receiving'}: {filename}"
        self.title_label = QLabel(label_text)
        self.title_label.setWordWrap(True)
        self.title_label.setStyleSheet("font-size:11px; color:#555;")
        layout.addWidget(self.title_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

    def set_progress(self, percent: int):
        self.progress_bar.setValue(percent)


# ============================================================================
# CHAT WINDOW
# ============================================================================

class ChatWindow(QWidget):
    """The WhatsApp-style chat room window shown after a successful
    handshake, for both the host and the connecting peer."""

    def __init__(self, sock: socket.socket, crypto: CryptoManager,
                 session_label: str, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.crypto = crypto
        self.setWindowTitle(f"P2P Secure Chat - {session_label}")
        self.resize(520, 680)

        self._incoming_progress_bubble = None
        self._active_send_thread = None

        self._build_ui()

        self.receive_thread = ChatReceiveThread(self.sock, self.crypto)
        self.receive_thread.text_received.connect(self._on_text_received)
        self.receive_thread.file_incoming.connect(self._on_file_incoming)
        self.receive_thread.file_progress.connect(self._on_file_progress)
        self.receive_thread.file_received.connect(self._on_file_received)
        self.receive_thread.connection_lost.connect(self._on_connection_lost)
        self.receive_thread.error_occurred.connect(self._on_error)
        self.receive_thread.start()

    # ---- UI construction -------------------------------------------------

    def _build_ui(self):
        main_layout = QVBoxLayout(self)

        # Scrollable message history
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("background-color:#ECE5DD;")

        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setAlignment(Qt.AlignTop)
        self.messages_layout.addStretch(1)
        self.scroll_area.setWidget(self.messages_container)

        main_layout.addWidget(self.scroll_area, stretch=1)

        # Input row
        input_row = QHBoxLayout()

        self.attach_btn = QPushButton("\U0001F4CE")  # 📎
        self.attach_btn.setToolTip("Attach a file")
        self.attach_btn.setFixedWidth(40)
        self.attach_btn.clicked.connect(self._on_attach_clicked)
        input_row.addWidget(self.attach_btn)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.returnPressed.connect(self._on_send_clicked)
        input_row.addWidget(self.message_input, stretch=1)

        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self._on_send_clicked)
        input_row.addWidget(self.send_btn)

        main_layout.addLayout(input_row)

    def _add_bubble(self, bubble: QFrame, is_own: bool):
        row = QHBoxLayout()
        if is_own:
            row.addStretch(1)
            row.addWidget(bubble)
        else:
            row.addWidget(bubble)
            row.addStretch(1)

        row_widget = QWidget()
        row_widget.setLayout(row)

        insert_index = self.messages_layout.count() - 1  # before the stretch
        self.messages_layout.insertWidget(insert_index, row_widget)

        QTimer.singleShot(10, self._scroll_to_bottom)
        return row_widget

    def _scroll_to_bottom(self):
        bar = self.scroll_area.verticalScrollBar()
        bar.setValue(bar.maximum())

    # ---- Outgoing: text ----------------------------------------------

    def _on_send_clicked(self):
        text = self.message_input.text().strip()
        if not text:
            return
        try:
            send_text_frame(self.sock, self.crypto, text)
        except Exception as exc:
            self._on_error(f"Failed to send message: {exc}")
            return
        self._add_bubble(TextChatBubble("You", text, True), True)
        self.message_input.clear()

    # ---- Outgoing: file ------------------------------------------------

    def _on_attach_clicked(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Select a file to send")
        if not filepath:
            return

        filename = os.path.basename(filepath)
        progress_bubble = ProgressChatBubble("You", filename, True)
        self._add_bubble(progress_bubble, True)

        self._active_send_thread = FileSendThread(self.sock, self.crypto, filepath)
        self._active_send_thread.progress_updated.connect(progress_bubble.set_progress)
        self._active_send_thread.send_finished.connect(
            lambda fname, fpath, fsize, bubble=progress_bubble:
            self._on_send_finished(fname, fpath, fsize, bubble)
        )
        self._active_send_thread.error_occurred.connect(self._on_error)
        self._active_send_thread.start()

    def _on_send_finished(self, filename, filepath, filesize, progress_bubble):
        progress_bubble.set_progress(100)
        ext = os.path.splitext(filename)[1].lower()
        if ext in IMAGE_EXTENSIONS:
            pixmap = QPixmap(filepath)
            if not pixmap.isNull():
                self._add_bubble(
                    ImageChatBubble("You", filename, pixmap, True), True
                )
                return
        self._add_bubble(FileChatBubble("You", filename, filesize, True), True)

    # ---- Incoming --------------------------------------------------------

    def _on_text_received(self, text: str):
        self._add_bubble(TextChatBubble("Partner", text, False), False)

    def _on_file_incoming(self, filename: str, filesize: int):
        self._incoming_progress_bubble = ProgressChatBubble("Partner", filename, False)
        self._add_bubble(self._incoming_progress_bubble, False)

    def _on_file_progress(self, percent: int):
        if self._incoming_progress_bubble:
            self._incoming_progress_bubble.set_progress(percent)

    def _on_file_received(self, filename: str, local_path: str, filesize: int):
        self._incoming_progress_bubble = None
        ext = os.path.splitext(filename)[1].lower()
        if ext in IMAGE_EXTENSIONS:
            pixmap = QPixmap(local_path)
            if not pixmap.isNull():
                self._add_bubble(
                    ImageChatBubble("Partner", filename, pixmap, False), False
                )
                return
        self._add_bubble(FileChatBubble("Partner", filename, filesize, False), False)

    # ---- Error / disconnect handling --------------------------------------

    def _on_connection_lost(self, message: str):
        QMessageBox.warning(self, "Connection Lost", message)

    def _on_error(self, message: str):
        QMessageBox.critical(self, "Error", message)

    # ---- Cleanup -----------------------------------------------------

    def closeEvent(self, event):
        try:
            self.receive_thread.stop()
        except Exception:
            pass
        try:
            if self._active_send_thread and self._active_send_thread.isRunning():
                self._active_send_thread.wait(1000)
        except Exception:
            pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        try:
            self.receive_thread.wait(2000)
        except Exception:
            pass
        event.accept()


# ============================================================================
# MAIN WINDOW: TABS FOR HOSTING / CONNECTING
# ============================================================================

class HostTab(QWidget):
    """'Receive Session / Chat Room' tab: generates a Session ID + PIN and
    waits for an incoming connection."""

    connection_established = Signal(object, object, str)  # sock, crypto, label

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_thread = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignTop)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Receive Session")
        title.setFont(QFont("", 14, QFont.Bold))
        layout.addWidget(title)

        info = QLabel(
            "Click Start to open a secure tunnel to the internet. Share the "
            "generated Session ID and PIN with your partner so they can "
            "connect from anywhere."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        token_row = QHBoxLayout()
        token_row.addWidget(QLabel("ngrok Authtoken (optional):"))
        self.authtoken_input = QLineEdit()
        self.authtoken_input.setPlaceholderText(
            "Leave empty to use a previously configured token"
        )
        token_row.addWidget(self.authtoken_input, stretch=1)
        layout.addLayout(token_row)

        self.start_btn = QPushButton("Start Session")
        self.start_btn.clicked.connect(self._on_start_clicked)
        layout.addWidget(self.start_btn)

        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("color:#555;")
        layout.addWidget(self.status_label)

        result_frame = QFrame()
        result_frame.setStyleSheet(
            "QFrame { border: 1px solid #ccc; border-radius: 6px; padding: 10px; }"
        )
        result_layout = QVBoxLayout(result_frame)

        id_row = QHBoxLayout()
        id_row.addWidget(QLabel("Session ID:"))
        self.session_id_value = QLineEdit()
        self.session_id_value.setReadOnly(True)
        id_row.addWidget(self.session_id_value, stretch=1)
        result_layout.addLayout(id_row)

        pin_row = QHBoxLayout()
        pin_row.addWidget(QLabel("PIN:"))
        self.pin_value = QLineEdit()
        self.pin_value.setReadOnly(True)
        pin_row.addWidget(self.pin_value, stretch=1)
        result_layout.addLayout(pin_row)

        layout.addWidget(result_frame)
        layout.addStretch(1)

    def _on_start_clicked(self):
        self.start_btn.setEnabled(False)
        self.status_label.setText("Status: Opening tunnel...")
        self.setup_thread = HostSetupThread(self.authtoken_input.text())
        self.setup_thread.session_ready.connect(self._on_session_ready)
        self.setup_thread.waiting_for_client.connect(self._on_waiting)
        self.setup_thread.handshake_failed.connect(self._on_handshake_failed)
        self.setup_thread.connected.connect(self._on_connected)
        self.setup_thread.error_occurred.connect(self._on_error)
        self.setup_thread.start()

    def _on_session_ready(self, session_id, pin):
        self.session_id_value.setText(session_id)
        self.pin_value.setText(pin)

    def _on_waiting(self):
        self.status_label.setText("Status: Waiting for partner to connect...")

    def _on_handshake_failed(self, message):
        self.status_label.setText("Status: Handshake failed.")
        self.start_btn.setEnabled(True)
        QMessageBox.warning(self, "Handshake Failed", message)

    def _on_connected(self, sock, crypto):
        self.status_label.setText("Status: Connected! Opening chat room...")
        self.start_btn.setEnabled(True)
        self.connection_established.emit(
            sock, crypto, self.session_id_value.text()
        )

    def _on_error(self, message):
        self.status_label.setText("Status: Error.")
        self.start_btn.setEnabled(True)
        QMessageBox.critical(self, "Error", message)

    def cleanup(self):
        if self.setup_thread:
            self.setup_thread.cleanup()
            try:
                self.setup_thread.terminate()
                self.setup_thread.wait(500)
            except Exception:
                pass


class ConnectTab(QWidget):
    """'Connect to Partner' tab: enter a partner's Session ID and PIN."""

    connection_established = Signal(object, object, str)  # sock, crypto, label

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_thread = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignTop)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Connect to Partner")
        title.setFont(QFont("", 14, QFont.Bold))
        layout.addWidget(title)

        info = QLabel(
            "Enter the Session ID and PIN shared by your partner to start a "
            "secure end-to-end encrypted chat and file transfer session."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        id_row = QHBoxLayout()
        id_row.addWidget(QLabel("Session ID:"))
        self.session_id_input = QLineEdit()
        self.session_id_input.setPlaceholderText("e.g. 0.tcp.ngrok.io:12345")
        id_row.addWidget(self.session_id_input, stretch=1)
        layout.addLayout(id_row)

        pin_row = QHBoxLayout()
        pin_row.addWidget(QLabel("PIN:"))
        self.pin_input = QLineEdit()
        self.pin_input.setPlaceholderText("6-character PIN")
        self.pin_input.setMaxLength(6)
        pin_row.addWidget(self.pin_input, stretch=1)
        layout.addLayout(pin_row)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self._on_connect_clicked)
        layout.addWidget(self.connect_btn)

        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("color:#555;")
        layout.addWidget(self.status_label)

        layout.addStretch(1)

    def _on_connect_clicked(self):
        session_id = self.session_id_input.text().strip()
        pin = self.pin_input.text().strip()
        if not session_id or not pin:
            QMessageBox.warning(
                self, "Missing Information",
                "Please enter both the Session ID and the PIN."
            )
            return

        self.connect_btn.setEnabled(False)
        self.status_label.setText("Status: Connecting...")

        self.setup_thread = ClientSetupThread(session_id, pin)
        self.setup_thread.connected.connect(self._on_connected)
        self.setup_thread.handshake_failed.connect(self._on_handshake_failed)
        self.setup_thread.error_occurred.connect(self._on_error)
        self.setup_thread.start()

    def _on_connected(self, sock, crypto):
        self.status_label.setText("Status: Connected! Opening chat room...")
        self.connect_btn.setEnabled(True)
        self.connection_established.emit(
            sock, crypto, self.session_id_input.text().strip()
        )

    def _on_handshake_failed(self, message):
        self.status_label.setText("Status: Handshake failed.")
        self.connect_btn.setEnabled(True)
        QMessageBox.warning(self, "Handshake Failed", message)

    def _on_error(self, message):
        self.status_label.setText("Status: Error.")
        self.connect_btn.setEnabled(True)
        QMessageBox.critical(self, "Connection Error", message)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("P2P Secure Chat & File Transfer")
        self.resize(560, 480)

        self.chat_windows = []  # keep references alive

        self.tabs = QTabWidget()
        self.host_tab = HostTab()
        self.connect_tab = ConnectTab()
        self.tabs.addTab(self.host_tab, "Receive Session / Chat Room")
        self.tabs.addTab(self.connect_tab, "Connect to Partner")
        self.setCentralWidget(self.tabs)

        self.host_tab.connection_established.connect(self._open_chat_window)
        self.connect_tab.connection_established.connect(self._open_chat_window)

    def _open_chat_window(self, sock, crypto, label):
        chat_window = ChatWindow(sock, crypto, label)
        self.chat_windows.append(chat_window)
        chat_window.show()

    def closeEvent(self, event):
        # Clean up any open chat windows (closes sockets, stops threads).
        for chat_window in list(self.chat_windows):
            try:
                chat_window.close()
            except Exception:
                pass

        # Kill the ngrok tunnel / listening socket if the host flow was used.
        try:
            self.host_tab.cleanup()
        except Exception:
            pass

        event.accept()


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("P2P Secure Chat & File Transfer")

    if ngrok is None:
        QMessageBox.critical(
            None, "Missing Dependency",
            "pyngrok is not installed.\n\nInstall it with:\n"
            "    pip install pyngrok"
        )

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
