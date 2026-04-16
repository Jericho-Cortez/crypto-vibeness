# Crypto-vibeness

Chat TCP avec authentification par mot de passe, chiffrement symétrique TEA des messages de salon, et DM chiffrés de bout en bout (Jour 3.5).

## Fichiers d'authentification / chiffrement

- `this_is_safe.txt` : table `username:pbkdf2:iterations:salt:digest` (base64)
- `password_rules.json` : règles de complexité relues au démarrage du serveur
- `user_keys_do_not_steal_plz.txt` : table `username:pbkdf2:iterations:salt:key` (base64)
- `users/<username>/key.txt` : clé locale client dérivée du secret de chiffrement (messages de salon)
- `users/<username>/key.pub` et `users/<username>/key.priv` : paire RSA locale pour E2EE
- `users/<username>/peers/<peer>.pub` : cache local des clés publiques des pairs

## Lancement

- Serveur : `python3 server.py`
- Client : `python3 client.py [host] [port]`

## Commandes

- `/rooms`, `/create <room> [password]`, `/join <room> [password]`, `/quit`
- `/dm <username> <message>` : envoi 1‑1 E2EE (clé de session pair-à-pair + signature RSA)
