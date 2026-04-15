# Crypto-vibeness

Chat TCP avec authentification par mot de passe et chiffrement symétrique TEA des messages.

## Fichiers d'authentification / chiffrement

- `this_is_safe.txt` : table `username:pbkdf2:iterations:salt:digest` (base64)
- `password_rules.json` : règles de complexité relues au démarrage du serveur
- `user_keys_do_not_steal_plz.txt` : table `username:pbkdf2:iterations:salt:key` (base64)
- `users/<username>/key.txt` : clé locale client dérivée du secret de chiffrement

## Lancement

- Serveur : `python3 server.py`
- Client : `python3 client.py [host] [port]`
