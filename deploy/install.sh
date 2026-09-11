#!/usr/bin/env bash
# Provision CRA Sentinel Watchtower on a Debian/Ubuntu host.
# Everything it needs: python3, git, and outbound HTTPS.
set -euo pipefail

PREFIX=/opt/cra-watchtower
STATE=/var/lib/cra-watchtower
SECRETS=/etc/cra-watchtower

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

echo "==> packages"
apt-get update -qq
apt-get install -y -qq python3 python3-venv git ca-certificates

echo "==> service user"
id -u watchtower &>/dev/null || useradd --system --home "$STATE" \
    --shell /usr/sbin/nologin watchtower

echo "==> directories"
install -d -o watchtower -g watchtower -m 0750 "$STATE" "$STATE/work"
install -d -o root -g watchtower -m 0750 "$SECRETS"

echo "==> virtualenv"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip cra-sentinel

echo "==> configuration"
if [[ ! -f "$STATE/config.json" ]]; then
  sudo -u watchtower CRA_WATCHTOWER_HOME="$STATE" \
      "$PREFIX/venv/bin/cra" watchtower init
fi

if [[ ! -f "$SECRETS/secrets.env" ]]; then
  cat > "$SECRETS/secrets.env" <<'ENV'
# Credentials only. Readable by the service user, nobody else.
CRA_SMTP_PASSWORD=
CRA_WEBHOOK_URL=
ENV
  chown root:watchtower "$SECRETS/secrets.env"
  chmod 0640 "$SECRETS/secrets.env"
fi

echo "==> systemd"
install -m 0644 cra-watchtower.service /etc/systemd/system/
install -m 0644 cra-watchtower.timer /etc/systemd/system/
install -m 0644 cra-watchtower-dashboard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cra-watchtower.timer
systemctl enable --now cra-watchtower-dashboard.service

cat <<DONE

  Installed.

  1. Fill in $SECRETS/secrets.env  (SMTP password, webhook URL)
  2. Fill in $STATE/config.json    (recipients, SMTP host)
  3. Add your first product:

       sudo -u watchtower CRA_WATCHTOWER_HOME=$STATE \\
           $PREFIX/venv/bin/cra watchtower add "Client — Product 1.0" \\
           --source https://github.com/client/product.git \\
           --supplier "Client GmbH"

  4. Sweep once by hand to confirm delivery works:

       sudo systemctl start cra-watchtower.service
       sudo journalctl -u cra-watchtower.service -n 40

  Dashboard on 127.0.0.1:8788 — put a reverse proxy with authentication in
  front of it before exposing it. It shows your clients' exposure.

DONE
