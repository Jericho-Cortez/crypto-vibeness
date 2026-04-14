#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
from typing import Optional, Tuple

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5050
ANSI_RESET = "\033[0m"


def json_line(payload: dict) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


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


def connect(host: str, port: int) -> tuple[socket.socket, dict]:
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
    rfile.close()
    return sock, response


def main() -> None:
    host, port = parse_args()
    while True:
        try:
            sock, welcome = connect(host, port)
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
            print_room_list(payload.get("rooms", []))
            safe_print("Commands: /rooms, /create <room> [password], /join <room> [password], /quit")
        elif msg_type == "room_list":
            print_room_list(payload.get("rooms", []))
        elif msg_type == "message":
            color = payload.get("color", "")
            username = payload.get("username", "")
            room = payload.get("room", "")
            text = payload.get("text", "")
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
                sock.sendall(json_line({"type": "message", "text": line}))
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
