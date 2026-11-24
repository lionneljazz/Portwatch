# portwatch

Petit tableau de bord **temps réel** des ports TCP ouverts sur un serveur Linux : un rond vert, orange ou rouge, le nom du service, et ce qui ouvre le port (processus, chemin, PID, etc.).

Pensé pour les développeurs sur machine modeste : un seul fichier Python, **aucune dépendance**, environ 10 Mo de RAM.

```
🟢 8081  Tomcat    /usr/lib/jvm/java-8-openjdk-amd64/bin/java
🟢 4200  Angular   /usr/bin/node
🔴 6321  SFTP      Accès SFTP
```

## Fonctionnalités

- Pastille **verte** (actif), **rouge** (inactif) ou **orange** (port occupé par un autre processus que celui attendu, ou application qui ne répond plus en HTTP)
- Affiche aussi tous les autres ports ouverts avec le nom du processus
- Détails au clic ou au survol : PID, utilisateur, mémoire, durée de fonctionnement, adresse d'écoute, exécutable, dossier de travail, commande complète
- Test HTTP optionnel avec code et temps de réponse
- Badge « exposé » (accessible depuis le réseau) ou « local »
- Boutons : Ouvrir, Copier l'URL, Démarrer, Redémarrer, Arrêter (SIGTERM), Forcer (SIGKILL), Copier la commande
- Filtre, pause, journal des changements, état dans le titre de l'onglet
- Mode terminal (`--cli`)

## Prérequis

- Linux avec `ss` (paquet `iproute2`, présent par défaut sur Ubuntu)
- Python 3.6 ou supérieur
- `sudo` pour voir tous les processus et utiliser les boutons d'action

Testé avec Ubuntu, Tomcat 8 et Java 8.

## Installation

```bash
sudo mkdir -p /opt/portwatch
sudo cp portwatch.py /opt/portwatch/
sudo python3 /opt/portwatch/portwatch.py
```

Ouvrez ensuite http://127.0.0.1:9999

## Configuration

Tout se règle en haut de `portwatch.py` :

```python
HOST, PORT = "127.0.0.1", 9999   # "0.0.0.0" pour y accéder depuis un autre PC
TOKEN = ""                       # accès via http://ip:9999/?token=MONTOKEN
ENABLE_ACTIONS = True            # boutons Démarrer / Redémarrer / Arrêter
REFRESH = 3                      # secondes entre deux rafraîchissements

WATCH = [
    {"port": 8081, "name": "Tomcat", "desc": "Serveur d'applications",
     "expect": "java", "web": True, "check": "/",
     "start":   ["systemctl", "start", "tomcat8"],
     "restart": ["systemctl", "restart", "tomcat8"]},
    {"port": 4200, "name": "Angular", "desc": "ng serve", "expect": "node", "web": True},
    {"port": 6321, "name": "SFTP", "desc": "Accès SFTP", "expect": "sshd"},
]
```

| Champ | Rôle |
|-------|------|
| `port`, `name`, `desc` | Obligatoires : port surveillé, nom et description affichés |
| `expect` | Mot attendu dans le processus (sinon pastille orange) |
| `web` | `True` pour afficher les boutons « Ouvrir » et « Copier l'URL » |
| `check` | Chemin HTTP testé (ex. `"/"`) |
| `start`, `restart` | Commande (liste d'arguments) lancée par les boutons |

Les ports de `WATCH` sont toujours affichés (rouge s'ils sont fermés). Les autres ports ouverts apparaissent en dessous.

## Lancement automatique (systemd)

Créez `/etc/systemd/system/portwatch.service` :

```ini
[Unit]
Description=Port watch
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/portwatch/portwatch.py
Restart=always
MemoryMax=30M

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now portwatch
```

## Mode terminal

```bash
sudo python3 portwatch.py --cli
```

## Sécurité

- Par défaut, portwatch n'écoute que sur `127.0.0.1`.
- Si vous utilisez `HOST = "0.0.0.0"`, les boutons d'action sont désactivés tant qu'un `TOKEN` n'est pas défini. Limitez aussi l'accès par pare-feu ou VPN, car la page expose des lignes de commande.
- Les boutons n'agissent que sur le processus qui écoute réellement le port affiché.
- Les commandes `start` et `restart` viennent uniquement du fichier de configuration, jamais du navigateur.

## Limites

- Seuls les ports **TCP en écoute** sont affichés (pas l'UDP)
- Sans `sudo`, le nom du processus peut être indisponible pour les ports d'autres utilisateurs

## Licence

MIT (à adapter selon votre choix)
