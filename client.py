#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
from getpass import getpass
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import threading
from typing import Optional, Tuple

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5050
ANSI_RESET = "\033[0m"
MESSAGE_KEY_ITERATIONS = 200_000
MESSAGE_KEY_SIZE = 16
KEY_DIR = Path("users")


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
    user_dir = KEY_DIR / username
    user_dir.mkdir(parents=True, exist_ok=True)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    content = f"pbkdf2:{iterations}:{salt_b64}:{key_b64}\n"
    (user_dir / "key.txt").write_text(content, encoding="utf-8")


def print_room_list(rooms: list[dict]) -> None:
    print("Rooms:")
    for room in rooms:
        marker = " [locked]" if room.get("protected") else ""
        print(f"  - {room.get('name')} {marker} ({room.get('members')} users)")


def parse_args() -> Tuple[str, int]:
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


def connect(host: str, port: int) -> tuple[socket.socket, dict, bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    rfile = sock.makefile("r", encoding="utf-8", newline="\n")
    username = prompt_username()
    sock.sendall(json_line({"type": "hello", "username": username}))
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
        sock.sendall(
            json_line(
                {
                    "type": "key_auth",
                    "key": base64.b64encode(message_key).decode("ascii"),
                }
            )
        )
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
            return sock, response, message_key
        rfile.close()
        sock.close()
        raise ValueError("unexpected encryption key reply")


def main() -> None:
    host, port = parse_args()
    while True:
        try:
            sock, welcome, message_key = connect(host, port)
            break
        except ValueError as exc:
            print(exc)
            print("Choose another username.")
        except (ConnectionError, OSError, json.JSONDecodeError) as exc:
            print(f"Connection failed: {exc}")
            return

    stop_event = threading.Event()
    print_lock = threading.Lock()
    rfile = sock.makefile("r", encoding="utf-8", newline="\n")

    def safe_print(message: str) -> None:
        with print_lock:
            print(message, flush=True)

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
            safe_print("Commands: /rooms, /create <room> [password], /join <room> [password], /quit")
        elif msg_type == "room_list":
            print_room_list(payload.get("rooms", []))
        elif msg_type == "message":
            color = payload.get("color", "")
            username = payload.get("username", "")
            room = payload.get("room", "")
            ciphertext = str(payload.get("ciphertext", ""))
            if not ciphertext:
                text = str(payload.get("text", ""))
            else:
                try:
                    text = decrypt_text(ciphertext, message_key)
                except ValueError:
                    text = "<unable to decrypt message>"
            safe_print(f"[{timestamp}] [{room}] {color}{username}{ANSI_RESET}: {text}")
        elif msg_type == "system":
            room = payload.get("room", "")
            safe_print(f"[{timestamp}] [{room}] {payload.get('message', '')}")
        elif msg_type == "error":
            safe_print(f"Error: {payload.get('message', '')}")
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
                print("Commands: /rooms, /create <room> [password], /join <room> [password], /quit")
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
