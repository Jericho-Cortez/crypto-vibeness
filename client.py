#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
from getpass import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import threading
from typing import Any, Optional

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5050
ANSI_RESET = "\033[0m"
MESSAGE_KEY_ITERATIONS = 200_000
MESSAGE_KEY_SIZE = 16
KEY_DIR = Path("users")
RSA_BITS = 2048
PUBLIC_EXPONENT = 65537

PublicKey = tuple[int, int]
PrivateKey = tuple[int, int, int]


def json_line(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def derive_message_key(secret: str, salt: bytes, iterations: int = MESSAGE_KEY_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iterations, dklen=MESSAGE_KEY_SIZE)


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
    encrypted_blocks: list[bytes] = []
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
    decrypted_blocks: list[bytes] = []
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


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = egcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def mod_inverse(a: int, modulus: int) -> int:
    gcd, x, _ = egcd(a, modulus)
    if gcd != 1:
        raise ValueError("no modular inverse")
    return x % modulus


def is_probable_prime(value: int, rounds: int = 24) -> bool:
    if value < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    for prime in small_primes:
        if value == prime:
            return True
        if value % prime == 0:
            return False
    d = value - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(value - 3) + 2
        x = pow(a, d, value)
        if x in (1, value - 1):
            continue
        witness = True
        for _ in range(r - 1):
            x = pow(x, 2, value)
            if x == value - 1:
                witness = False
                break
        if witness:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= 1
        candidate |= 1 << (bits - 1)
        if is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = RSA_BITS) -> tuple[PrivateKey, PublicKey]:
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        modulus = p * q
        totient = (p - 1) * (q - 1)
        if totient % PUBLIC_EXPONENT == 0:
            continue
        private_exponent = mod_inverse(PUBLIC_EXPONENT, totient)
        return (modulus, PUBLIC_EXPONENT, private_exponent), (modulus, PUBLIC_EXPONENT)


def serialize_public_key(public_key: PublicKey) -> dict[str, str]:
    return {"n": str(public_key[0]), "e": str(public_key[1])}


def parse_public_key(payload: Any) -> Optional[PublicKey]:
    if not isinstance(payload, dict):
        return None
    try:
        modulus = int(str(payload.get("n")))
        exponent = int(str(payload.get("e")))
    except (TypeError, ValueError):
        return None
    if modulus <= 0 or exponent <= 1:
        return None
    return modulus, exponent


def rsa_encrypt_bytes(message: bytes, public_key: PublicKey) -> bytes:
    modulus, exponent = public_key
    key_size = (modulus.bit_length() + 7) // 8
    if len(message) > key_size - 11:
        raise ValueError("message too long for rsa block")
    padding_len = key_size - len(message) - 3
    padding = bytearray()
    while len(padding) < padding_len:
        value = secrets.randbelow(255) + 1
        padding.append(value)
    block = b"\x00\x02" + bytes(padding) + b"\x00" + message
    encrypted = pow(int.from_bytes(block, "big"), exponent, modulus)
    return encrypted.to_bytes(key_size, "big")


def rsa_decrypt_bytes(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    modulus, _, private_exponent = private_key
    key_size = (modulus.bit_length() + 7) // 8
    if len(ciphertext) != key_size:
        raise ValueError("invalid rsa block length")
    decrypted = pow(int.from_bytes(ciphertext, "big"), private_exponent, modulus)
    block = decrypted.to_bytes(key_size, "big")
    if len(block) < 11 or block[0] != 0 or block[1] != 2:
        raise ValueError("invalid rsa padding")
    separator = block.find(b"\x00", 2)
    if separator < 10:
        raise ValueError("invalid rsa padding")
    return block[separator + 1 :]


def rsa_sign_bytes(message: bytes, private_key: PrivateKey) -> bytes:
    modulus, _, private_exponent = private_key
    key_size = (modulus.bit_length() + 7) // 8
    digest = hashlib.sha256(message).digest()
    signature = pow(int.from_bytes(digest, "big"), private_exponent, modulus)
    return signature.to_bytes(key_size, "big")


def rsa_verify_bytes(message: bytes, signature: bytes, public_key: PublicKey) -> bool:
    modulus, exponent = public_key
    key_size = (modulus.bit_length() + 7) // 8
    if len(signature) != key_size:
        return False
    expected = int.from_bytes(hashlib.sha256(message).digest(), "big")
    received = pow(int.from_bytes(signature, "big"), exponent, modulus)
    return received == expected


def signed_blob(kind: str, sender: str, recipient: str, body: str) -> bytes:
    return f"{kind}|{sender}|{recipient}|{body}".encode("utf-8")


def user_dir(username: str) -> Path:
    return KEY_DIR / username


def load_or_create_identity(username: str) -> tuple[PrivateKey, PublicKey]:
    directory = user_dir(username)
    directory.mkdir(parents=True, exist_ok=True)
    pub_path = directory / "key.pub"
    priv_path = directory / "key.priv"
    if pub_path.exists() and priv_path.exists():
        pub_data = json.loads(pub_path.read_text(encoding="utf-8"))
        priv_data = json.loads(priv_path.read_text(encoding="utf-8"))
        public_key = parse_public_key(pub_data)
        if public_key is None:
            raise ValueError("invalid stored public key")
        try:
            modulus = int(str(priv_data["n"]))
            exponent = int(str(priv_data["e"]))
            private_exponent = int(str(priv_data["d"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid stored private key") from exc
        private_key: PrivateKey = (modulus, exponent, private_exponent)
        if (modulus, exponent) != public_key:
            raise ValueError("public and private key mismatch")
        return private_key, public_key
    private_key, public_key = generate_rsa_keypair()
    pub_path.write_text(json.dumps(serialize_public_key(public_key), separators=(",", ":")) + "\n", encoding="utf-8")
    priv_path.write_text(
        json.dumps({"n": str(private_key[0]), "e": str(private_key[1]), "d": str(private_key[2])}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return private_key, public_key


def peer_key_path(local_username: str, peer_username: str) -> Path:
    peer_dir = user_dir(local_username) / "peers"
    peer_dir.mkdir(parents=True, exist_ok=True)
    return peer_dir / f"{peer_username}.pub"


def save_peer_public_key(local_username: str, peer_username: str, public_key: PublicKey) -> None:
    path = peer_key_path(local_username, peer_username)
    path.write_text(json.dumps(serialize_public_key(public_key), separators=(",", ":")) + "\n", encoding="utf-8")


def load_peer_public_key(local_username: str, peer_username: str) -> Optional[PublicKey]:
    path = peer_key_path(local_username, peer_username)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return parse_public_key(payload)


def prompt_encryption_secret(is_register: bool) -> str:
    while True:
        secret = getpass("Encryption secret: ")
        if is_register:
            confirmation = getpass("Confirm encryption secret: ")
            if secret != confirmation:
                print("Encryption secrets do not match.")
                continue
        if not secret:
            print("Encryption secret cannot be empty.")
            continue
        return secret


def save_local_key(username: str, iterations: int, salt: bytes, key: bytes) -> None:
    directory = user_dir(username)
    directory.mkdir(parents=True, exist_ok=True)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    content = f"pbkdf2:{iterations}:{salt_b64}:{key_b64}\n"
    (directory / "key.txt").write_text(content, encoding="utf-8")


def print_room_list(rooms: list[dict]) -> None:
    print("Rooms:")
    for room in rooms:
        marker = " [locked]" if room.get("protected") else ""
        print(f"  - {room.get('name')} {marker} ({room.get('members')} users)")


def parse_args() -> tuple[str, int]:
    parser = argparse.ArgumentParser(description="IRC-style multi-user chat client")
    parser.add_argument("args", nargs="*")
    parsed = parser.parse_args()
    args = parsed.args
    if len(args) > 2:
        parser.error("usage: client.py [host] [port]")
    if not args:
        return DEFAULT_HOST, DEFAULT_PORT
    if len(args) == 1:
        if args[0].isdigit():
            return DEFAULT_HOST, int(args[0])
        return args[0], DEFAULT_PORT
    host, port = args[0], int(args[1])
    return host, port


def prompt_username() -> str:
    while True:
        username = input("Username: ").strip()
        if username:
            return username
        print("Username cannot be empty.")


def prompt_new_password() -> tuple[str, str]:
    while True:
        password = getpass("Choose password: ")
        confirmation = getpass("Confirm password: ")
        if password == confirmation:
            return password, confirmation
        print("Passwords do not match.")


def print_policy(policy: list[str]) -> None:
    if not policy:
        return
    print("Password policy:")
    for rule in policy:
        print(f"  - {rule}")


def connect(host: str, port: int) -> tuple[socket.socket, dict, bytes, str, PrivateKey]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    rfile = sock.makefile("r", encoding="utf-8", newline="\n")
    username = prompt_username()
    private_key, public_key = load_or_create_identity(username)
    sock.sendall(json_line({"type": "hello", "username": username, "public_key": serialize_public_key(public_key)}))
    raw = rfile.readline()
    if not raw:
        rfile.close()
        sock.close()
        raise ConnectionError("server closed the connection")
    response = json.loads(raw)
    if response.get("type") == "error":
        rfile.close()
        sock.close()
        raise ValueError(str(response.get("message", "login refused")))
    if response.get("type") != "auth_required":
        rfile.close()
        sock.close()
        raise ValueError("unexpected authentication response")

    mode = response.get("mode")
    if mode == "register":
        print("No account found. Creating a new one.")
        print_policy(response.get("policy", []))
    elif mode != "login":
        rfile.close()
        sock.close()
        raise ValueError("unsupported authentication mode")

    while True:
        if mode == "register":
            password, confirmation = prompt_new_password()
            sock.sendall(json_line({"type": "auth", "password": password, "confirm": confirmation}))
        else:
            password = getpass("Password: ")
            sock.sendall(json_line({"type": "auth", "password": password}))
        raw = rfile.readline()
        if not raw:
            rfile.close()
            sock.close()
            raise ConnectionError("server closed the connection")
        response = json.loads(raw)
        if response.get("type") == "auth_error":
            print(f"Error: {response.get('message', 'authentication failed')}")
            continue
        if response.get("type") == "key_required":
            break
        rfile.close()
        sock.close()
        raise ValueError("unexpected authentication reply")

    iterations = int(response.get("iterations", MESSAGE_KEY_ITERATIONS))
    try:
        salt_b64 = str(response.get("salt", ""))
        salt = base64.b64decode(salt_b64, validate=True)
    except (TypeError, ValueError, base64.binascii.Error):
        rfile.close()
        sock.close()
        raise ValueError("invalid key exchange parameters")
    key_mode = str(response.get("mode", mode))
    while True:
        secret = prompt_encryption_secret(key_mode == "register")
        message_key = derive_message_key(secret, salt, iterations)
        sock.sendall(json_line({"type": "key_auth", "key": base64.b64encode(message_key).decode("ascii")}))
        raw = rfile.readline()
        if not raw:
            rfile.close()
            sock.close()
            raise ConnectionError("server closed the connection")
        response = json.loads(raw)
        if response.get("type") == "key_error":
            print(f"Error: {response.get('message', 'invalid encryption secret')}")
            continue
        if response.get("type") == "welcome":
            save_local_key(username, iterations, salt, message_key)
            rfile.close()
            return sock, response, message_key, username, private_key
        rfile.close()
        sock.close()
        raise ValueError("unexpected encryption key reply")


def main() -> None:
    host, port = parse_args()
    while True:
        try:
            sock, welcome, message_key, username, private_key = connect(host, port)
            break
        except ValueError as exc:
            print(exc)
            print("Choose another username.")
        except (ConnectionError, OSError, json.JSONDecodeError) as exc:
            print(f"Connection failed: {exc}")
            return

    stop_event = threading.Event()
    print_lock = threading.Lock()
    state_lock = threading.Lock()
    rfile = sock.makefile("r", encoding="utf-8", newline="\n")
    peer_public_keys: dict[str, PublicKey] = {}
    peer_session_keys: dict[str, bytes] = {}
    pending_key_events: dict[str, threading.Event] = {}
    pending_key_errors: dict[str, str] = {}

    def safe_print(message: str) -> None:
        with print_lock:
            print(message, flush=True)

    def cache_peer_key(peer_username: str, public_key: PublicKey) -> None:
        with state_lock:
            peer_public_keys[peer_username] = public_key
        save_peer_public_key(username, peer_username, public_key)

    def lookup_peer_key(peer_username: str) -> Optional[PublicKey]:
        with state_lock:
            cached = peer_public_keys.get(peer_username)
        if cached is not None:
            return cached
        cached = load_peer_public_key(username, peer_username)
        if cached is not None:
            cache_peer_key(peer_username, cached)
        return cached

    def remember_peer_key_from_payload(peer_username: str, payload: Any) -> Optional[PublicKey]:
        parsed = parse_public_key(payload)
        if parsed is None:
            return None
        cache_peer_key(peer_username, parsed)
        return parsed

    def request_peer_key(peer_username: str, timeout_seconds: float = 8.0) -> Optional[PublicKey]:
        key = lookup_peer_key(peer_username)
        if key is not None:
            return key
        event = threading.Event()
        with state_lock:
            pending_key_events[peer_username] = event
            pending_key_errors.pop(peer_username, None)
        try:
            sock.sendall(json_line({"type": "command", "command": "peer_key", "username": peer_username}))
        except OSError:
            with state_lock:
                pending_key_events.pop(peer_username, None)
            return None
        event.wait(timeout=timeout_seconds)
        with state_lock:
            pending_key_events.pop(peer_username, None)
            error_message = pending_key_errors.pop(peer_username, "")
        if error_message:
            safe_print(f"Error: {error_message}")
            return None
        return lookup_peer_key(peer_username)

    def render(payload: dict) -> None:
        msg_type = payload.get("type")
        timestamp = payload.get("timestamp", "")
        if msg_type == "welcome":
            safe_print(f"[{timestamp}] Connected as {payload.get('username')} in room {payload.get('room')}")
            color = payload.get("color", "")
            if color:
                safe_print(f"Your color: {color}{payload.get('color_name', '')}{ANSI_RESET}")
            if payload.get("account_created"):
                strength = payload.get("password_strength", {})
                if strength:
                    safe_print(
                        f"Password strength: {strength.get('bits', '?')} bits ({strength.get('label', '')})"
                    )
            print_room_list(payload.get("rooms", []))
            safe_print("Commands: /rooms, /create <room> [password], /join <room> [password], /dm <username> <message>, /quit")
        elif msg_type == "room_list":
            print_room_list(payload.get("rooms", []))
        elif msg_type == "message":
            color = payload.get("color", "")
            sender = payload.get("username", "")
            room = payload.get("room", "")
            ciphertext = str(payload.get("ciphertext", ""))
            if not ciphertext:
                text = str(payload.get("text", ""))
            else:
                try:
                    text = decrypt_text(ciphertext, message_key)
                except ValueError:
                    text = "<unable to decrypt message>"
            safe_print(f"[{timestamp}] [{room}] {color}{sender}{ANSI_RESET}: {text}")
        elif msg_type == "peer_key":
            peer_username = str(payload.get("username", "")).strip()
            public_key = remember_peer_key_from_payload(peer_username, payload.get("public_key"))
            with state_lock:
                event = pending_key_events.get(peer_username)
            if event is not None:
                event.set()
            if peer_username and public_key is None:
                safe_print(f"Warning: invalid public key received for {peer_username}.")
        elif msg_type == "pair_key":
            sender = str(payload.get("from", "")).strip()
            encrypted_key_b64 = str(payload.get("encrypted_key", "")).strip()
            signature_b64 = str(payload.get("signature", "")).strip()
            sender_public_key = remember_peer_key_from_payload(sender, payload.get("public_key"))
            if not sender or not encrypted_key_b64 or not signature_b64:
                safe_print("Warning: malformed pair key payload received.")
                return
            if sender_public_key is None:
                safe_print(f"Warning: missing sender public key for {sender}.")
                return
            try:
                signature = base64.b64decode(signature_b64, validate=True)
            except (ValueError, base64.binascii.Error):
                safe_print(f"Warning: invalid key signature from {sender}.")
                return
            if not rsa_verify_bytes(signed_blob("pair_key", sender, username, encrypted_key_b64), signature, sender_public_key):
                safe_print(f"Warning: rejected key exchange from {sender} (invalid signature).")
                return
            try:
                encrypted_key = base64.b64decode(encrypted_key_b64, validate=True)
                key_material = rsa_decrypt_bytes(encrypted_key, private_key)
            except (ValueError, base64.binascii.Error):
                safe_print(f"Warning: unable to decrypt key exchange from {sender}.")
                return
            if len(key_material) < MESSAGE_KEY_SIZE:
                safe_print(f"Warning: rejected weak key exchange from {sender}.")
                return
            with state_lock:
                peer_session_keys[sender] = key_material[:MESSAGE_KEY_SIZE]
            safe_print(f"[{timestamp}] Secure DM session key established with {sender}.")
        elif msg_type == "direct_message":
            sender = str(payload.get("from", "")).strip()
            ciphertext = str(payload.get("ciphertext", "")).strip()
            signature_b64 = str(payload.get("signature", "")).strip()
            sender_public_key = remember_peer_key_from_payload(sender, payload.get("public_key"))
            if not sender or not ciphertext or not signature_b64:
                safe_print("Warning: malformed direct message payload received.")
                return
            if sender_public_key is None:
                safe_print(f"Warning: missing sender public key for {sender}.")
                return
            try:
                signature = base64.b64decode(signature_b64, validate=True)
            except (ValueError, base64.binascii.Error):
                safe_print(f"Warning: invalid signature encoding from {sender}.")
                return
            if not rsa_verify_bytes(signed_blob("direct_message", sender, username, ciphertext), signature, sender_public_key):
                safe_print(f"Warning: rejected direct message from {sender} (invalid signature).")
                return
            with state_lock:
                dm_key = peer_session_keys.get(sender)
            if dm_key is None:
                safe_print(f"Warning: no DM session key for {sender}; message rejected.")
                return
            try:
                text = decrypt_text(ciphertext, dm_key)
            except ValueError:
                safe_print(f"Warning: unable to decrypt direct message from {sender}.")
                return
            safe_print(f"[{timestamp}] [DM] {sender}: {text}")
        elif msg_type == "system":
            room = payload.get("room", "")
            safe_print(f"[{timestamp}] [{room}] {payload.get('message', '')}")
        elif msg_type == "error":
            error_message = str(payload.get("message", ""))
            match = re.fullmatch(r"user '([^']+)' is not online", error_message)
            if match:
                offline_peer = match.group(1)
                with state_lock:
                    pending_key_errors[offline_peer] = error_message
                    event = pending_key_events.get(offline_peer)
                if event is not None:
                    event.set()
            safe_print(f"Error: {error_message}")
        elif msg_type == "goodbye":
            safe_print("Disconnected.")
            stop_event.set()
        else:
            safe_print(json.dumps(payload, ensure_ascii=False))

    def listener() -> None:
        try:
            while not stop_event.is_set():
                raw = rfile.readline()
                if not raw:
                    stop_event.set()
                    safe_print("Connection closed by server.")
                    break
                render(json.loads(raw))
        except (OSError, json.JSONDecodeError):
            stop_event.set()
            safe_print("Connection lost.")

    thread = threading.Thread(target=listener, daemon=True)
    thread.start()

    try:
        while not stop_event.is_set():
            try:
                line = input("> ").strip()
            except EOFError:
                line = "/quit"
            if not line:
                continue
            if line.startswith("/"):
                parts = line[1:].split(maxsplit=2)
                command = parts[0].lower()
                if command == "quit":
                    sock.sendall(json_line({"type": "command", "command": "quit"}))
                    stop_event.set()
                    break
                if command == "rooms":
                    sock.sendall(json_line({"type": "command", "command": "rooms"}))
                    continue
                if command in {"create", "join"}:
                    if len(parts) < 2:
                        print("Usage: /create <room> [password]" if command == "create" else "Usage: /join <room> [password]")
                        continue
                    room = parts[1]
                    password = parts[2] if len(parts) == 3 else None
                    sock.sendall(
                        json_line(
                            {
                                "type": "command",
                                "command": command,
                                "room": room,
                                "password": password,
                            }
                        )
                    )
                    continue
                if command == "dm":
                    if len(parts) < 3:
                        print("Usage: /dm <username> <message>")
                        continue
                    peer_username = parts[1].strip()
                    plaintext = parts[2]
                    if not peer_username:
                        print("Usage: /dm <username> <message>")
                        continue
                    if peer_username == username:
                        print("You cannot DM yourself.")
                        continue

                    with state_lock:
                        dm_key = peer_session_keys.get(peer_username)
                    if dm_key is None:
                        peer_public_key = request_peer_key(peer_username)
                        if peer_public_key is None:
                            print(f"Unable to fetch public key for '{peer_username}'.")
                            continue
                        dm_key = os.urandom(MESSAGE_KEY_SIZE)
                        try:
                            encrypted_key = rsa_encrypt_bytes(dm_key, peer_public_key)
                        except ValueError:
                            print(f"Failed to encrypt a DM key for '{peer_username}'.")
                            continue
                        encrypted_key_b64 = base64.b64encode(encrypted_key).decode("ascii")
                        key_signature = rsa_sign_bytes(
                            signed_blob("pair_key", username, peer_username, encrypted_key_b64),
                            private_key,
                        )
                        sock.sendall(
                            json_line(
                                {
                                    "type": "pair_key",
                                    "to": peer_username,
                                    "encrypted_key": encrypted_key_b64,
                                    "signature": base64.b64encode(key_signature).decode("ascii"),
                                }
                            )
                        )
                        with state_lock:
                            peer_session_keys[peer_username] = dm_key

                    ciphertext = encrypt_text(plaintext, dm_key)
                    signature = rsa_sign_bytes(signed_blob("direct_message", username, peer_username, ciphertext), private_key)
                    sock.sendall(
                        json_line(
                            {
                                "type": "direct_message",
                                "to": peer_username,
                                "ciphertext": ciphertext,
                                "signature": base64.b64encode(signature).decode("ascii"),
                            }
                        )
                    )
                    continue
                print("Commands: /rooms, /create <room> [password], /join <room> [password], /dm <username> <message>, /quit")
            else:
                sock.sendall(json_line({"type": "message", "ciphertext": encrypt_text(line, message_key)}))
    except (BrokenPipeError, OSError):
        pass
    finally:
        stop_event.set()
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()
