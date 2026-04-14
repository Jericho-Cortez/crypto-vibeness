#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

DEFAULT_PORT = 5050
HOST = "0.0.0.0"
LOG_PREFIX = "log_"
GENERAL_ROOM = "general"

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

    def handle_rooms(self, session: Session) -> None:
        session.send({"type": "room_list", "timestamp": now_string(), "rooms": self.room_snapshot()})

    def handle_message(self, session: Session, text: str) -> None:
        payload = {
            "type": "message",
            "timestamp": now_string(),
            "room": session.room,
            "username": session.username,
            "color": session.color_code,
            "color_name": session.color_name,
            "text": text,
        }
        self.broadcast(session.room, payload)
        self.log(session.username, session.addr, "message", f"room={session.room} text={text}")

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
        try:
            raw = rfile.readline()
            if not raw:
                return None
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                conn.sendall(
                    json_line({"type": "error", "timestamp": now_string(), "message": "invalid handshake"})
                )
                return None
            if payload.get("type") != "hello":
                conn.sendall(
                    json_line({"type": "error", "timestamp": now_string(), "message": "expected hello"})
                )
                return None
            username = str(payload.get("username", "")).strip()
            if not username:
                conn.sendall(
                    json_line({"type": "error", "timestamp": now_string(), "message": "username required"})
                )
                return None
            with self.lock:
                if username in self.sessions:
                    conn.sendall(
                        json_line(
                            {
                                "type": "error",
                                "timestamp": now_string(),
                                "message": f"username '{username}' is already in use",
                            }
                        )
                    )
                    return None
            color_code, color_name = pick_color(username)
            session = Session(
                conn=conn,
                addr=addr,
                username=username,
                room=GENERAL_ROOM,
                color_code=color_code,
                color_name=color_name,
            )
            self.add_session(session)
            self.log(username, addr, "connect", f"room={GENERAL_ROOM} color={color_name}")
            session.send(
                {
                    "type": "welcome",
                    "timestamp": now_string(),
                    "username": username,
                    "room": GENERAL_ROOM,
                    "color": color_code,
                    "color_name": color_name,
                    "message": "connected",
                    "rooms": self.room_snapshot(),
                    "help": [
                        "/rooms",
                        "/create <room> [password]",
                        "/join <room> [password]",
                        "/quit",
                    ],
                }
            )
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
                    text = str(payload.get("text", "")).rstrip()
                    if text:
                        self.handle_message(session, text)
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
