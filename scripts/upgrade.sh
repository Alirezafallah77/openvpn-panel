#!/bin/bash
# Update a previous v0.1 installation without replacing CA, settings or users.
set -Eeuo pipefail
umask 077
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Ubuntu 24.04 required.' >&2; exit 1; }
[[ -f /etc/openvpn-panel/panel.env && -x /opt/openvpn-panel/.venv/bin/python ]] || { echo 'Existing installation required.' >&2; exit 1; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)-$$
install -d -m 0700 /var/backups/openvpn-panel
/usr/local/sbin/openvpn-panelctl backup "/var/backups/openvpn-panel/before-upgrade-$STAMP.tar.gz"
tar --exclude=.venv --exclude=__pycache__ -czf "/var/backups/openvpn-panel/code-before-$STAMP.tar.gz" -C /opt openvpn-panel
# Dependency installation before downtime; versions of existing libraries stay pinned.
/opt/openvpn-panel/.venv/bin/pip install -r "$SOURCE/requirements.txt"
chmod -R a+rX /opt/openvpn-panel/.venv
systemctl stop openvpn-panel-backup.timer openvpn-panel-backup.service 2>/dev/null || true
systemctl stop openvpn-server@panel openvpn-panel-accounting openvpn-panel openvpn-panel-pki
trap 'echo "Upgrade interrupted. Private rollback archives are in /var/backups/openvpn-panel. Inspect journals before starting services." >&2' ERR
for file in app.py quota.py hook_entry.py collector_entry.py broker_entry.py scheduler_entry.py metrics.py requirements.txt; do
  install -m 0644 "$SOURCE/$file" /opt/openvpn-panel/
done
for dir in vpn templates static; do
  cp -r "$SOURCE/$dir/." "/opt/openvpn-panel/$dir/"
done
chown -R root:root /opt/openvpn-panel
install -d -o root -g openvpn-panel -m 0710 /var/lib/openvpn-panel-backups /var/lib/openvpn-panel-status
install -m 0755 "$SOURCE/scripts/panelctl.py" /usr/local/sbin/openvpn-panelctl
install -m 0644 "$SOURCE"/deploy/*.service "$SOURCE"/deploy/*.timer /etc/systemd/system/
install -m 0644 "$SOURCE/deploy/openvpn-override.conf" /etc/systemd/system/openvpn-server@panel.service.d/panel.conf
systemctl daemon-reload
/usr/local/sbin/openvpn-panelctl restart
systemctl enable --now openvpn-panel-backup.timer
for service in openvpn-panel openvpn-panel-pki openvpn-panel-accounting openvpn-server@panel; do
  systemctl is-active --quiet "$service"
done
echo 'Upgrade complete. Users, usage, VPN keys, admin password and endpoint were preserved.'
echo "Private rollback archives: /var/backups/openvpn-panel/*$STAMP.tar.gz"
