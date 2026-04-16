#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

PASSWORD_STORE_PATH = Path("this_is_safe.txt")
PASSWORD_RULES_PATH = Path("password_rules.json")
KEY_STORE_PATH = Path("user_keys_do_not_steal_plz.txt")
DEFAULT_PASSWORD_RULES = {
    "min_length": 12,
    "min_lowercase": 1,
    "min_uppercase": 1,
    "min_digit": 1,
    "min_symbol": 1,
    "forbidden_substrings": [],
}

DEFAULT_PORT = 5050
HOST = "0.0.0.0"
LOG_PREFIX = "log_"
GENERAL_ROOM = "general"
MESSAGE_KEY_ITERATIONS = 200_000
MESSAGE_KEY_SIZE = 16
RSA_KEY_SIZE = 2048

ANSI_RESET = "\033[0m"
ANSI_COLORS = [
    ("\033[31m", "red"),
    ("\033[32m", "green"),
    ("\033[33m", "yellow"),
    ("\033[34m", "blue"),
    ("\033[35m", "magenta"),
    ("\033[36m", "cyan"),
    ("\033[91m", "bright-red"),
    ("\033[92m", "bright-green"),
]


def json_line(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def now_string() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_name() -> str:
    return datetime.now().strftime("log_%Y-%m-%d_%H-%M-%S.txt")


def pick_color(username: str) -> tuple[str, str]:
    digest = hashlib.sha256(username.lower().encode("utf-8")).digest()
    index = digest[0] % len(ANSI_COLORS)
    return ANSI_COLORS[index]


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with per-user salt.
    
    Format: pbkdf2:iterations:salt:digest (all base64 except algo and iterations)
    """
    if salt is None:
        salt = os.urandom(16)
    
    iterations = 100_000
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
    
    salt_b64 = base64.b64encode(salt).decode('ascii')
    key_b64 = base64.b64encode(key).decode('ascii')
    
    return f"pbkdf2:{iterations}:{salt_b64}:{key_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored PBKDF2 hash.
    
    Handles both new PBKDF2 format and legacy MD5 format for backwards compatibility.
    """
    if stored_hash.startswith('pbkdf2:'):
        parts = stored_hash.split(':')
        if len(parts) != 4:
            return False
        algo, iterations_str, salt_b64, key_b64 = parts
        try:
            iterations = int(iterations_str)
            salt = base64.b64decode(salt_b64)
            stored_key = base64.b64decode(key_b64)
        except (ValueError, TypeError):
            return False
        
        candidate_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
        return hmac.compare_digest(stored_key, candidate_key)
    else:
        digest = hashlib.md5(password.encode("utf-8")).digest()
        candidate_hash = base64.b64encode(digest).decode("ascii")
        return hmac.compare_digest(stored_hash, candidate_hash)


def tea_encrypt_block(block: bytes, key: bytes) -> bytes:
    v0 = int.from_bytes(block[:4], "big")
    v1 = int.from_bytes(block[4:], "big")
    k0 = int.from_bytes(key[0:4], "big")
    k1 = int.from_bytes(key[4:8], "big")
    k2 = int.from_bytes(key[8:12], "big")
    k3 = int.from_bytes(key[12:16], "big")
    delta = 0x9E3779B9
    total = 0
    for _ in range(32):
        total = (total + delta) & 0xFFFFFFFF
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def tea_decrypt_block(block: bytes, key: bytes) -> bytes:
    v0 = int.from_bytes(block[:4], "big")
    v1 = int.from_bytes(block[4:], "big")
    k0 = int.from_bytes(key[0:4], "big")
    k1 = int.from_bytes(key[4:8], "big")
    k2 = int.from_bytes(key[8:12], "big")
    k3 = int.from_bytes(key[12:16], "big")
    delta = 0x9E3779B9
    total = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt_text(plaintext: str, key: bytes) -> str:
    data = plaintext.encode("utf-8")
    pad_len = 8 - (len(data) % 8)
    padded = data + bytes([pad_len] * pad_len)
    iv = os.urandom(8)
    previous = iv
    encrypted_blocks: List[bytes] = []
    for offset in range(0, len(padded), 8):
        block = padded[offset : offset + 8]
        mixed = xor_bytes(block, previous)
        encrypted = tea_encrypt_block(mixed, key)
        encrypted_blocks.append(encrypted)
        previous = encrypted
    return base64.b64encode(iv + b"".join(encrypted_blocks)).decode("ascii")


def decrypt_text(ciphertext_b64: str, key: bytes) -> str:
    try:
        raw = base64.b64decode(ciphertext_b64, validate=True)
    except (base64.binascii.Error, ValueError) as exc:
        raise ValueError("invalid encrypted payload") from exc
    if len(raw) < 16 or len(raw) % 8 != 0:
        raise ValueError("invalid encrypted payload length")
    iv = raw[:8]
    ciphertext = raw[8:]
    previous = iv
    decrypted_blocks: List[bytes] = []
    for offset in range(0, len(ciphertext), 8):
        block = ciphertext[offset : offset + 8]
        decrypted = tea_decrypt_block(block, key)
        plain_block = xor_bytes(decrypted, previous)
        decrypted_blocks.append(plain_block)
        previous = block
    padded = b"".join(decrypted_blocks)
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 8 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding")
    return padded[:-pad_len].decode("utf-8")


DUMMY_PASSWORD_HASH = hash_password("")


def estimate_password_entropy(password: str) -> float:
    pool = 0
    if any(char.islower() for char in password):
        pool += 26
    if any(char.isupper() for char in password):
        pool += 26
    if any(char.isdigit() for char in password):
        pool += 10
    if any(not char.isalnum() for char in password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def password_strength_label(entropy_bits: float) -> str:
    if entropy_bits < 60:
        return "weak"
    if entropy_bits < 90:
        return "medium"
    return "strong"


@dataclass
class PasswordRules:
    min_length: int = 12
    min_lowercase: int = 1
    min_uppercase: int = 1
    min_digit: int = 1
    min_symbol: int = 1
    forbidden_substrings: List[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "PasswordRules":
        if not path.exists():
            path.write_text(
                json.dumps(DEFAULT_PASSWORD_RULES, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            min_length=int(data.get("min_length", 12)),
            min_lowercase=int(data.get("min_lowercase", 1)),
            min_uppercase=int(data.get("min_uppercase", 1)),
            min_digit=int(data.get("min_digit", 1)),
            min_symbol=int(data.get("min_symbol", 1)),
            forbidden_substrings=[
                str(item).lower() for item in data.get("forbidden_substrings", []) if str(item).strip()
            ],
        )

    def describe(self) -> List[str]:
        rules = [
            f"at least {self.min_length} characters",
            f"at least {self.min_lowercase} lowercase letter(s)",
            f"at least {self.min_uppercase} uppercase letter(s)",
            f"at least {self.min_digit} digit(s)",
            f"at least {self.min_symbol} symbol(s)",
            "must not contain the username",
        ]
        for forbidden in self.forbidden_substrings:
            rules.append(f"must not contain '{forbidden}'")
        return rules

    def validate(self, username: str, password: str) -> List[str]:
        errors: List[str] = []
        if len(password) < self.min_length:
            errors.append(f"password must contain at least {self.min_length} characters")
        if sum(char.islower() for char in password) < self.min_lowercase:
            errors.append(f"password must contain at least {self.min_lowercase} lowercase letter(s)")
        if sum(char.isupper() for char in password) < self.min_uppercase:
            errors.append(f"password must contain at least {self.min_uppercase} uppercase letter(s)")
        if sum(char.isdigit() for char in password) < self.min_digit:
            errors.append(f"password must contain at least {self.min_digit} digit(s)")
        if sum(not char.isalnum() for char in password) < self.min_symbol:
            errors.append(f"password must contain at least {self.min_symbol} symbol(s)")
        lowered_password = password.lower()
        lowered_username = username.lower()
        if lowered_username and lowered_username in lowered_password:
            errors.append("password must not contain the username")
        for forbidden in self.forbidden_substrings:
            if forbidden and forbidden in lowered_password:
                errors.append(f"password must not contain '{forbidden}'")
        return errors


@dataclass
class CredentialStore:
    path: Path
    users: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "CredentialStore":
        if not path.exists():
            path.write_text("", encoding="utf-8")
        users: Dict[str, str] = {}
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            if ":" not in line:
                raise ValueError(f"invalid credential line {line_number}: missing separator")
            username, password_hash = line.split(":", 1)
            username = username.strip()
            password_hash = password_hash.strip()
            if not username or not password_hash:
                raise ValueError(f"invalid credential line {line_number}: empty username or hash")
            users[username] = password_hash
        return cls(path=path, users=users)

    def save(self) -> None:
        lines = [f"{username}:{password_hash}" for username, password_hash in sorted(self.users.items())]
        content = "\n".join(lines)
        if content:
            content += "\n"
        temp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temp_path.write_text(content, encoding="utf-8")
        temp_path.replace(self.path)

    def get_hash(self, username: str) -> Optional[str]:
        return self.users.get(username)

    def set_user(self, username: str, password_hash: str) -> None:
        self.users[username] = password_hash
        self.save()

    def authenticate(self, username: str, password: str) -> bool:
        stored_hash = self.get_hash(username)
        if stored_hash is None:
            verify_password(password, DUMMY_PASSWORD_HASH)
            return False
        return verify_password(password, stored_hash)


@dataclass
class MessageKeyRecord:
    iterations: int
    salt: bytes
    key: bytes


@dataclass
class MessageKeyStore:
    path: Path
    users: Dict[str, MessageKeyRecord] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "MessageKeyStore":
        if not path.exists():
            path.write_text("", encoding="utf-8")
        users: Dict[str, MessageKeyRecord] = {}
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            parts = line.split(":")
            if len(parts) != 5:
                raise ValueError(f"invalid key line {line_number}: expected 5 fields")
            username, algo, iterations_str, salt_b64, key_b64 = parts
            if algo != "pbkdf2":
                raise ValueError(f"invalid key line {line_number}: unsupported algorithm '{algo}'")
            try:
                iterations = int(iterations_str)
                salt = base64.b64decode(salt_b64, validate=True)
                key = base64.b64decode(key_b64, validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise ValueError(f"invalid key line {line_number}: malformed base64 or iterations") from exc
            if not username or len(salt) < 12 or len(key) < MESSAGE_KEY_SIZE:
                raise ValueError(f"invalid key line {line_number}: empty username or weak key data")
            users[username] = MessageKeyRecord(iterations=iterations, salt=salt, key=key[:MESSAGE_KEY_SIZE])
        return cls(path=path, users=users)

    def save(self) -> None:
        lines: List[str] = []
        for username, record in sorted(self.users.items()):
            salt_b64 = base64.b64encode(record.salt).decode("ascii")
            key_b64 = base64.b64encode(record.key).decode("ascii")
            lines.append(f"{username}:pbkdf2:{record.iterations}:{salt_b64}:{key_b64}")
        content = "\n".join(lines)
        if content:
            content += "\n"
        temp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temp_path.write_text(content, encoding="utf-8")
        temp_path.replace(self.path)

    def get(self, username: str) -> Optional[MessageKeyRecord]:
        return self.users.get(username)

    def set_user(self, username: str, record: MessageKeyRecord) -> None:
        self.users[username] = record
        self.save()


@dataclass
class Room:
    name: str
    password: Optional[str] = None
    members: Set[str] = field(default_factory=set)

    @property
    def protected(self) -> bool:
        return self.password is not None


@dataclass
class Session:
    conn: socket.socket
    addr: tuple[str, int]
    username: str
    room: str
    color_code: str
    color_name: str
    message_key: bytes
    send_lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, payload: dict) -> None:
        with self.send_lock:
            self.conn.sendall(json_line(payload))


class ChatServer:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.lock = threading.RLock()
        self.rooms: Dict[str, Room] = {GENERAL_ROOM: Room(GENERAL_ROOM)}
        self.sessions: Dict[str, Session] = {}
        self.pending_auth: Set[str] = set()
        self.password_rules = PasswordRules.load(PASSWORD_RULES_PATH)
        self.credentials = CredentialStore.load(PASSWORD_STORE_PATH)
        self.message_keys = MessageKeyStore.load(KEY_STORE_PATH)
        
        self.server_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE, backend=default_backend())
        pub_key = self.server_key.public_key()
        pub_pem = pub_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.server_pub_key_pem = pub_pem.decode("ascii")
        
        self.log_path = log_name()
        self.log_file = open(self.log_path, "a", encoding="utf-8", buffering=1)

    def close(self) -> None:
        self.log_file.close()

    def log(self, username: str, addr: tuple[str, int], event: str, details: str = "") -> None:
        address = f"{addr[0]}:{addr[1]}"
        line = f"[{now_string()}] [{address}] [{username}] {event}"
        if details:
            line += f" - {details}"
        with self.lock:
            self.log_file.write(line + "\n")

    def send_payload(self, conn: socket.socket, payload: dict) -> None:
        conn.sendall(json_line(payload))

    def room_snapshot(self) -> List[dict]:
        with self.lock:
            rooms = []
            for room in sorted(self.rooms.values(), key=lambda item: item.name):
                rooms.append(
                    {
                        "name": room.name,
                        "protected": room.protected,
                        "members": len(room.members),
                    }
                )
            return rooms

    def send_to(self, username: str, payload: dict) -> None:
        with self.lock:
            session = self.sessions.get(username)
        if session is not None:
            session.send(payload)

    def broadcast(self, room_name: str, payload: dict, exclude: Optional[str] = None) -> None:
        with self.lock:
            room = self.rooms.get(room_name)
            if room is None:
                return
            recipients = [
                self.sessions[name]
                for name in room.members
                if name != exclude and name in self.sessions
            ]
        for session in recipients:
            try:
                session.send(payload)
            except OSError:
                self.disconnect(session.username, "send failure")

    def add_session(self, session: Session) -> None:
        with self.lock:
            self.sessions[session.username] = session
            self.rooms[GENERAL_ROOM].members.add(session.username)

    def reserve_username(self, username: str) -> bool:
        with self.lock:
            if username in self.sessions or username in self.pending_auth:
                return False
            self.pending_auth.add(username)
            return True

    def release_username(self, username: str) -> None:
        with self.lock:
            self.pending_auth.discard(username)

    def remove_session(self, username: str) -> Optional[Session]:
        with self.lock:
            session = self.sessions.pop(username, None)
            if session is None:
                return None
            room = self.rooms.get(session.room)
            if room is not None:
                room.members.discard(username)
            return session

    def create_room(self, name: str, password: Optional[str]) -> None:
        with self.lock:
            if name in self.rooms:
                raise ValueError(f"room '{name}' already exists")
            self.rooms[name] = Room(name=name, password=password or None)

    def move_session(self, session: Session, target_room: str) -> tuple[str, str]:
        with self.lock:
            previous_room = session.room
            if previous_room == target_room:
                raise ValueError(f"you are already in room '{target_room}'")
            room = self.rooms.get(target_room)
            if room is None:
                raise ValueError(f"room '{target_room}' does not exist")
            old_room = self.rooms.get(previous_room)
            if old_room is not None:
                old_room.members.discard(session.username)
            room.members.add(session.username)
            session.room = target_room
            return previous_room, target_room

    def join_room(self, session: Session, room_name: str, password: Optional[str]) -> None:
        with self.lock:
            room = self.rooms.get(room_name)
            if room is None:
                raise ValueError(f"room '{room_name}' does not exist")
            if room.password is not None and room.password != (password or None):
                raise ValueError(f"wrong password for room '{room_name}'")
        self.move_session(session, room_name)

    def create_and_join_room(self, session: Session, room_name: str, password: Optional[str]) -> str:
        previous_room = session.room
        self.create_room(room_name, password)
        self.move_session(session, room_name)
        return previous_room

    def auth_prompt(self, username: str, mode: str) -> dict:
        return {
            "type": "auth_required",
            "timestamp": now_string(),
            "username": username,
            "mode": mode,
            "policy": self.password_rules.describe(),
        }

    def auth_error(self, message: str) -> dict:
        return {"type": "auth_error", "timestamp": now_string(), "message": message}

    def key_prompt(self, username: str, mode: str, salt: bytes, iterations: int) -> dict:
        return {
            "type": "key_required",
            "timestamp": now_string(),
            "username": username,
            "mode": mode,
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode("ascii"),
            "algorithm": "pbkdf2-tea",
            "server_public_key": self.server_pub_key_pem,
        }

    def key_error(self, message: str) -> dict:
        return {"type": "key_error", "timestamp": now_string(), "message": message}

    def handle_rooms(self, session: Session) -> None:
        session.send({"type": "room_list", "timestamp": now_string(), "rooms": self.room_snapshot()})

    def handle_message(self, session: Session, ciphertext: str) -> None:
        text = decrypt_text(ciphertext, session.message_key)
        timestamp = now_string()
        with self.lock:
            room = self.rooms.get(session.room)
            if room is None:
                return
            recipients = [self.sessions[name] for name in room.members if name in self.sessions]
        for recipient in recipients:
            payload = {
                "type": "message",
                "timestamp": timestamp,
                "room": session.room,
                "username": session.username,
                "color": session.color_code,
                "color_name": session.color_name,
                "ciphertext": encrypt_text(text, recipient.message_key),
            }
            try:
                recipient.send(payload)
            except OSError:
                self.disconnect(recipient.username, "send failure")
        self.log(session.username, session.addr, "message", f"room={session.room} ciphertext={ciphertext}")

    def handle_create(self, session: Session, room_name: str, password: Optional[str]) -> None:
        previous_room = self.create_and_join_room(session, room_name, password)
        self.log(
            session.username,
            session.addr,
            "room_created",
            f"room={room_name} protected={'yes' if password else 'no'}",
        )
        self.broadcast(
            previous_room,
            {
                "type": "system",
                "timestamp": now_string(),
                "room": previous_room,
                "message": f"{session.username} left room '{previous_room}'",
            },
            exclude=session.username,
        )
        self.broadcast(
            room_name,
            {
                "type": "system",
                "timestamp": now_string(),
                "room": room_name,
                "message": f"{session.username} joined room '{room_name}'",
            },
            exclude=session.username,
        )
        self.send_to(
            session.username,
            {
                "type": "system",
                "timestamp": now_string(),
                "room": session.room,
                "message": f"created and joined room '{room_name}'",
            },
        )

    def handle_join(self, session: Session, room_name: str, password: Optional[str]) -> None:
        previous_room = session.room
        self.join_room(session, room_name, password)
        self.log(session.username, session.addr, "room_joined", f"from={previous_room} to={room_name}")
        self.broadcast(
            previous_room,
            {
                "type": "system",
                "timestamp": now_string(),
                "room": previous_room,
                "message": f"{session.username} left room '{previous_room}'",
            },
            exclude=session.username,
        )
        self.broadcast(
            room_name,
            {
                "type": "system",
                "timestamp": now_string(),
                "room": room_name,
                "message": f"{session.username} joined room '{room_name}'",
            },
            exclude=session.username,
        )
        self.send_to(
            session.username,
            {
                "type": "system",
                "timestamp": now_string(),
                "room": room_name,
                "message": f"joined room '{room_name}'",
            },
        )

    def handle_quit(self, session: Session) -> None:
        self.send_to(
            session.username,
            {
                "type": "goodbye",
                "timestamp": now_string(),
                "message": "bye",
            },
        )
        raise ConnectionAbortedError

    def welcome_payload(
        self,
        session: Session,
        account_created: bool,
        password_strength: Optional[dict] = None,
    ) -> dict:
        payload = {
            "type": "welcome",
            "timestamp": now_string(),
            "username": session.username,
            "room": session.room,
            "color": session.color_code,
            "color_name": session.color_name,
            "message": "connected",
            "rooms": self.room_snapshot(),
            "help": [
                "/rooms",
                "/create <room> [password]",
                "/join <room> [password]",
                "/quit",
            ],
            "account_created": account_created,
        }
        if password_strength is not None:
            payload["password_strength"] = password_strength
        return payload

    def disconnect(self, username: str, reason: str) -> None:
        session = self.remove_session(username)
        if session is None:
            return
        self.broadcast(
            session.room,
            {
                "type": "system",
                "timestamp": now_string(),
                "room": session.room,
                "message": f"{username} disconnected",
            },
            exclude=username,
        )
        self.log(username, session.addr, "disconnect", reason)
        try:
            session.conn.close()
        except OSError:
            pass

    def register(self, conn: socket.socket, addr: tuple[str, int]) -> Optional[Session]:
        rfile = conn.makefile("r", encoding="utf-8", newline="\n")
        username: Optional[str] = None
        try:
            raw = rfile.readline()
            if not raw:
                return None
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                self.send_payload(conn, {"type": "error", "timestamp": now_string(), "message": "invalid handshake"})
                return None
            if payload.get("type") != "hello":
                self.send_payload(conn, {"type": "error", "timestamp": now_string(), "message": "expected hello"})
                return None
            username = str(payload.get("username", "")).strip()
            if not username:
                self.send_payload(conn, {"type": "error", "timestamp": now_string(), "message": "username required"})
                return None
            if not self.reserve_username(username):
                self.send_payload(
                    conn,
                    {
                        "type": "error",
                        "timestamp": now_string(),
                        "message": f"username '{username}' is already in use",
                    },
                )
                return None

            with self.lock:
                account_exists = self.credentials.get_hash(username) is not None
            mode = "login" if account_exists else "register"
            self.send_payload(conn, self.auth_prompt(username, mode))

            account_created = False
            password_strength: Optional[dict] = None
            while True:
                raw = rfile.readline()
                if not raw:
                    return None
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    self.send_payload(conn, self.auth_error("invalid authentication payload"))
                    continue
                if payload.get("type") != "auth":
                    self.send_payload(conn, self.auth_error("expected auth payload"))
                    continue

                password = str(payload.get("password", ""))
                if mode == "login":
                    with self.lock:
                        authenticated = self.credentials.authenticate(username, password)
                    if authenticated:
                        break
                    self.send_payload(conn, self.auth_error("incorrect password"))
                    continue

                confirmation = str(payload.get("confirm", ""))
                if password != confirmation:
                    self.send_payload(conn, self.auth_error("password confirmation does not match"))
                    continue
                errors = self.password_rules.validate(username, password)
                if errors:
                    self.send_payload(conn, self.auth_error("; ".join(errors)))
                    continue
                password_hash = hash_password(password)
                with self.lock:
                    self.credentials.set_user(username, password_hash)
                entropy_bits = estimate_password_entropy(password)
                password_strength = {
                    "bits": round(entropy_bits, 2),
                    "label": password_strength_label(entropy_bits),
                }
                account_created = True
                break

            with self.lock:
                key_record = self.message_keys.get(username)
            key_mode = mode
            if mode == "login" and key_record is None:
                key_mode = "register"
            if key_mode == "login":
                if key_record is None:
                    self.send_payload(conn, self.key_error("encryption key not initialized"))
                    return None
                key_salt = key_record.salt
                key_iterations = key_record.iterations
            else:
                key_salt = os.urandom(16)
                key_iterations = MESSAGE_KEY_ITERATIONS
            self.send_payload(conn, self.key_prompt(username, key_mode, key_salt, key_iterations))
            
            client_pub_key_pem: Optional[str] = None
            while True:
                raw = rfile.readline()
                if not raw:
                    return None
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    self.send_payload(conn, self.key_error("invalid payload"))
                    continue
                if payload.get("type") == "client_public_key":
                    try:
                        client_pub_key_pem = str(payload.get("public_key", ""))
                        serialization.load_pem_public_key(client_pub_key_pem.encode(), backend=default_backend())
                    except Exception:
                        self.send_payload(conn, self.key_error("invalid client public key"))
                        continue
                    self.send_payload(conn, {"type": "encapsulate_key", "timestamp": now_string()})
                    break
                self.send_payload(conn, self.key_error("expected client_public_key"))
                continue
            
            session_key: Optional[bytes] = None
            while True:
                raw = rfile.readline()
                if not raw:
                    return None
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    self.send_payload(conn, self.key_error("invalid encapsulation payload"))
                    continue
                if payload.get("type") != "key_encapsulation":
                    self.send_payload(conn, self.key_error("expected key_encapsulation payload"))
                    continue
                
                try:
                    encapsulated_b64 = str(payload.get("encapsulated_key", ""))
                    encapsulated = base64.b64decode(encapsulated_b64, validate=True)
                    provided_key = self.server_key.decrypt(encapsulated, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                except Exception:
                    self.send_payload(conn, self.key_error("failed to decapsulate key"))
                    continue
                
                if len(provided_key) < MESSAGE_KEY_SIZE:
                    self.send_payload(conn, self.key_error("encryption key too short"))
                    continue
                provided_key = provided_key[:MESSAGE_KEY_SIZE]
                
                if key_mode == "login":
                    if key_record is None:
                        self.send_payload(conn, self.key_error("encryption key not initialized"))
                        continue
                    if hmac.compare_digest(key_record.key, provided_key):
                        session_key = provided_key
                        break
                    self.send_payload(conn, self.key_error("incorrect encryption secret"))
                    continue
                with self.lock:
                    self.message_keys.set_user(
                        username,
                        MessageKeyRecord(iterations=key_iterations, salt=key_salt, key=provided_key),
                    )
                session_key = provided_key
                break

            if session_key is None:
                return None

            color_code, color_name = pick_color(username)
            session = Session(
                conn=conn,
                addr=addr,
                username=username,
                room=GENERAL_ROOM,
                color_code=color_code,
                color_name=color_name,
                message_key=session_key,
            )
            self.add_session(session)
            self.log(
                username,
                addr,
                "connect",
                f"room={GENERAL_ROOM} color={color_name} auth={'created' if account_created else 'login'}",
            )
            session.send(self.welcome_payload(session, account_created, password_strength))
            self.broadcast(
                GENERAL_ROOM,
                {
                    "type": "system",
                    "timestamp": now_string(),
                    "room": GENERAL_ROOM,
                    "message": f"{username} joined room '{GENERAL_ROOM}'",
                },
                exclude=username,
            )
            return session
        finally:
            if username is not None:
                self.release_username(username)
            rfile.close()

    def client_loop(self, session: Session) -> None:
        rfile = session.conn.makefile("r", encoding="utf-8", newline="\n")
        try:
            while True:
                raw = rfile.readline()
                if not raw:
                    self.disconnect(session.username, "client closed connection")
                    return
                try:
                    payload = json.loads(raw)
                except json.JSONDecodeError:
                    session.send({"type": "error", "timestamp": now_string(), "message": "invalid json"})
                    continue
                msg_type = payload.get("type")
                if msg_type == "message":
                    ciphertext = str(payload.get("ciphertext", "")).strip()
                    if not ciphertext:
                        session.send({"type": "error", "timestamp": now_string(), "message": "ciphertext required"})
                        continue
                    try:
                        self.handle_message(session, ciphertext)
                    except ValueError:
                        session.send({"type": "error", "timestamp": now_string(), "message": "invalid encrypted message"})
                elif msg_type == "command":
                    command = str(payload.get("command", "")).strip().lower()
                    room_name = str(payload.get("room", "")).strip()
                    password = payload.get("password")
                    normalized_password = None if password is None else str(password).strip() or None
                    if command == "rooms":
                        self.handle_rooms(session)
                    elif command == "create":
                        if not room_name:
                            session.send(
                                {
                                    "type": "error",
                                    "timestamp": now_string(),
                                    "message": "room name required",
                                }
                            )
                            continue
                        try:
                            self.handle_create(session, room_name, normalized_password)
                        except ValueError as exc:
                            session.send({"type": "error", "timestamp": now_string(), "message": str(exc)})
                    elif command == "join":
                        if not room_name:
                            session.send(
                                {
                                    "type": "error",
                                    "timestamp": now_string(),
                                    "message": "room name required",
                                }
                            )
                            continue
                        try:
                            self.handle_join(session, room_name, normalized_password)
                        except ValueError as exc:
                            session.send({"type": "error", "timestamp": now_string(), "message": str(exc)})
                    elif command == "quit":
                        self.handle_quit(session)
                    else:
                        session.send(
                            {
                                "type": "error",
                                "timestamp": now_string(),
                                "message": f"unknown command '{command}'",
                            }
                        )
                else:
                    session.send(
                        {
                            "type": "error",
                            "timestamp": now_string(),
                            "message": f"unknown payload type '{msg_type}'",
                        }
                    )
        except ConnectionAbortedError:
            self.disconnect(session.username, "client quit")
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.disconnect(session.username, "connection lost")
        finally:
            rfile.close()

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen()
            print(f"Chat server listening on {self.host}:{self.port}")
            print(f"Logs written to {self.log_path}")
            try:
                while True:
                    conn, addr = server_sock.accept()
                    thread = threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True)
                    thread.start()
            except KeyboardInterrupt:
                print("\nShutting down server...")

    def handle_connection(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        with conn:
            session = None
            try:
                session = self.register(conn, addr)
                if session is None:
                    return
                self.client_loop(session)
            except (ConnectionAbortedError, OSError):
                if session is not None:
                    self.disconnect(session.username, "connection closed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IRC-style multi-user chat server")
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = ChatServer(HOST, args.port)
    try:
        server.serve_forever()
    finally:
        server.close()


if __name__ == "__main__":
    main()
