#!/bin/sh
# Démarrage de Postfix — instance Modoboa Startup Pack.
# La config (main.cf, master.cf, sql-*.cf, maps de relais) est déjà en place
# dans /etc/postfix, rendue par l'initContainer k8s.
set -e

# Table d'alias locale (vide mais requise).
: > /etc/postfix/aliases
newaliases 2>/dev/null || true

# Compile en base les maps texte (relais SMTP sortant par client).
for m in /etc/postfix/sender_relayhost /etc/postfix/sender_relay_passwd; do
    [ -f "$m" ] && postmap "$m"
done

postfix set-permissions 2>/dev/null || true
postfix check 2>&1 || true
exec postfix start-fg
