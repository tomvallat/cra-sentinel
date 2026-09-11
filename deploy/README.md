# Watchtower — déploiement

Le balayage manuel ne tient pas la promesse d'un abonnement. Si le catalogue
CISA KEV ajoute une CVE un mardi soir et que vous scannez le jeudi, vous avez
vendu une surveillance que vous ne fournissez pas — dans un métier où c'est
précisément ce manquement qui vous détruit.

Ce répertoire installe le balayage automatique.

## Ce que ça fait

Six fois par jour, pour chaque produit du portefeuille :

1. rafraîchit la source (`git fetch` si c'est un dépôt distant) ;
2. scanne, et compare au dernier état connu ;
3. si une vulnérabilité **devient** activement exploitée, **enregistre
   l'horodatage de prise de connaissance** puis envoie l'alerte ;
4. relance tant que l'alerte n'est pas acquittée.

L'horodatage est enregistré **avant** la tentative d'envoi. Si le serveur SMTP
est en panne, l'alerte n'est pas distribuée mais la preuve existe — c'est ce
qui compte devant un contrôle.

## Installation

```bash
sudo ./install.sh
```

Debian/Ubuntu. Prérequis : `python3`, `git`, HTTPS sortant. Rien d'autre.

Puis :

```bash
sudo nano /etc/cra-watchtower/secrets.env    # mot de passe SMTP, webhook
sudo nano /var/lib/cra-watchtower/config.json # destinataires, hôte SMTP

sudo -u watchtower CRA_WATCHTOWER_HOME=/var/lib/cra-watchtower \
    /opt/cra-watchtower/venv/bin/cra watchtower add "Acme — Gateway 3.2.1" \
    --source https://github.com/acme/gateway.git \
    --supplier "Acme Industrial GmbH" --member-state Germany

sudo systemctl start cra-watchtower.service   # premier balayage
sudo journalctl -u cra-watchtower.service -n 40
```

**Vérifiez que l'alerte arrive vraiment** avant de facturer un abonnement.
Une chaîne de notification non testée est une chaîne qui ne marche pas.

## Cadence

Quatre heures entre deux balayages, six fois par jour. Ce n'est pas un défaut
arbitraire : l'alerte précoce est due 24 h après la prise de connaissance, donc
un décalage de détection borné à 4 h laisse 20 h pour décider et déclarer.
Descendre sous l'heure n'apporte rien — le catalogue KEV n'est pas mis à jour
plus d'une fois par jour en pratique.

La relance part au bout de 8 h sans acquittement, pas 24 : il faut que
l'opérateur soit prévenu bien avant la fermeture de la fenêtre.

## Codes de sortie

`0` rien à signaler · `1` quelque chose demande votre attention · `2` erreur.

Le `1` est un signal, pas un échec de service — d'où le `SuccessExitStatus=0 1`
dans l'unité systemd, sans quoi le timer se marquerait en erreur à chaque
détection.

## Sécurité

Le service tourne sous un utilisateur dédié, sans privilèges, avec
`ProtectSystem=strict`. Il lit des arborescences clientes et parle à deux API
publiques ; il n'a rien à faire d'autre.

Le tableau de bord écoute sur `127.0.0.1` uniquement. **Il expose la posture de
vulnérabilité de vos clients et n'a aucune authentification.** Mettez un
reverse proxy authentifié devant avant toute exposition.

Les identifiants ne sont jamais dans `config.json` — uniquement dans
`secrets.env`, en `0640`. C'est ce qui vous permet de versionner la
configuration dans votre propre dépôt.

## Sans systemd

Voir `crontab.example`.

## Exploitation courante

```bash
cra watchtower status                    # horloges en cours, fraîcheur des scans
cra watchtower ack <slug> <CVE> --by <nom> --note "..."
cra watchtower run --only <slug>         # rebalayer un seul produit
cra watchtower dashboard -o rapport.html # export statique
```
