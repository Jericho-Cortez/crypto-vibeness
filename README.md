# Crypto-vibeness

Chat TCP avec authentification par mot de passe.

## Fichiers d'authentification

- `this_is_safe.txt` : table `username:hash_base64(md5)`
- `password_rules.json` : règles de complexité relues au démarrage du serveur

## Lancement

- Serveur : `python3 server.py`
- Client : `python3 client.py [host] [port]`
