# Crypto-vibeness

**Crypto-vibeness is a secure-by-default terminal chat experience**: a lightweight TCP chat server and client with account authentication, encrypted room messaging, and end-to-end encrypted direct messages.

It feels like old-school IRC, but with modern cryptographic primitives and cleaner onboarding: users can register and log in from the same client flow, join password-protected rooms, and open authenticated private conversations without external dependencies.

## Why this project stands out

- **Real auth flow, not a toy prompt**: account creation + login with server-side password policy enforcement.
- **Encrypted room messages**: shared message secret derived with PBKDF2 and used for symmetric message encryption.
- **E2EE direct messages**: per-user RSA identities, peer public-key discovery, signed key exchange, and signed encrypted DMs.
- **Multi-room collaboration**: room listing, creation, protected rooms, and join/leave broadcast events.
- **Operational visibility**: timestamped server logs with connection and messaging events.

## Core capabilities

- Username-based authentication (`register`/`login` mode auto-detected by server)
- Password hashing with PBKDF2-HMAC-SHA256 (legacy MD5 verification compatibility exists for older data)
- Room chat encryption using TEA in CBC-like chaining with random IV
- End-to-end encrypted 1:1 DMs with RSA-2048 key exchange and message signatures
- JSON-over-TCP line protocol for simple interoperability and debugging

## Quick start

```bash
# 1) Start the server (default port: 5050)
python3 server.py

# 2) Start one or more clients
python3 client.py
# or
python3 client.py <host> <port>
```

## In-app commands

- `/rooms`
- `/create <room> [password]`
- `/join <room> [password]`
- `/dm <username> <message>`
- `/quit`

## Security and key material files

- `this_is_safe.txt` — user credential store (`username:pbkdf2:iterations:salt:digest`)
- `password_rules.json` — password policy loaded at server startup
- `user_keys_do_not_steal_plz.txt` — stored room-message keys (`username:pbkdf2:iterations:salt:key`)
- `users/<username>/key.txt` — local derived room-message key data
- `users/<username>/key.pub` and `users/<username>/key.priv` — local RSA identity
- `users/<username>/peers/<peer>.pub` — cached peer public keys

## Project structure

- `server.py` — multi-client TCP server, auth/key onboarding, room + DM routing, logging
- `client.py` — interactive CLI client, auth prompts, encryption/decryption, command handling
- `password_rules.json` — customizable password constraints

## Notes

This project is ideal for learning and demonstrating protocol design, chat UX in terminal environments, and layered cryptography in Python. It is not positioned as a production-hardened secure messaging platform.
