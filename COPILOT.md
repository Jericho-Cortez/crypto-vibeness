# COPILOT.md

## Project: Secure Chat System (Python)

**Status:** Day 1 complete (multi-user chat, rooms, colors, logs, password-protected rooms).
**Files:** server.py, client.py, README.md, log_*.txt, password_rules.json, this_is_safe.txt.

---

## Remaining objectives

### Jour 2 – Password security & cracking
Use hashcat (apt/brew/docker) to crack md5_yolo.txt (hash: 35b95f7c0f63631c453220fb2a86f218)
  Mask: ?u?u?l?l?u?u?s, brute force mode.
  Store cracked message & command in md5_decrypted.txt.
Learn to crack all user passwords of length ≤5 efficiently.
Replace MD5 with a modern key-derivation function (e.g. Argon2, bcrypt, scrypt) with a **cost factor**. Store: username:algo:cost:salt:digest (base64).
Use **per‑user salt** (≥96 bits). Salt stored left of digest, separated by :.
**Test signal** after each feature.
**End:** Jour 2 - terminé

---

### Jour 2.5 – Symmetric encryption of all messages
Derive a **per‑user encryption key** from a user‑supplied secret (KDF with per‑user salt). Key ≥128 bits.
Server stores user_keys_do_not_steal_plz.txt with username:salt:encrypted_key? (format like passwords).
  Client stores key locally (e.g. ./users/<username>/key.txt).
Use **block cipher** (TEA, or via libsodium/OpenSSL). Encrypt every message before sending to server.
**Test signal** after each feature.
**End:** Jour 2.5 - terminé

---

### Jour 3 – Asymmetric key exchange (remove server‑side keys)
Client generates (or reuses) an **asymmetric key pair** before connecting.
Use asymmetric encryption to exchange a **symmetric session key** (key encapsulation).
Then continue with symmetric encryption (same as Jour 2.5).
Server no longer stores user_keys_do_not_steal_plz.txt.
  Client stores key.priv and key.pub.
**Test signal** after each feature.
**End:** Jour 3 - terminé

---

### Jour 3.5 – End‑to‑end encryption (E2EE) for 1‑1 chats
**Server is honest‑but‑curious** – routes messages faithfully but may read them.

1. **Public key distribution**
   - Client sends its public key to server on connect.
   - Server maintains {username: public_key} directory.
   - Clients cache public keys of peers.

2. **Session key establishment per pair**
   - Alice generates symmetric session key, encrypts it with Bob’s public key, sends via server.
   - Bob decrypts with his private key. Shared secret unknown to server.

3. **Message encryption**
   - Use the session key (symmetric cipher, same as Jour 2.5).
   - Server relays opaque blobs – logs show only ciphertext.

4. **Signatures**
   - Sign each message with sender’s private key.
   - Receiver verifies signature with sender’s public key.
   - Reject and warn on failure (e.g. after a byte flip via proxy).

**Test signal** after each step.
**End:** Jour 3.5 - terminé

---

## Constraints
**Python 3** only.
Code in **English**.
Keep exactly two files: server.py and client.py (plus auxiliary data files).
No frameworks (Flask, etc.).
**Signal test execution points** explicitly in your responses.

---

## Next action
Continue from **Jour 2**.
Run tests after implementing each bullet point.
At the end of each day’s work, output the exact line "Jour X - terminé".
