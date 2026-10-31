#!/bin/bash
# Ubuntu 24.04 NEW dedicated server installation. Never executes remote shell text.
set -Eeuo pipefail
umask 077
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ENDPOINT= DOMAIN= PASSWORD_FILE=
usage() {
  echo "Usage: sudo bash scripts/install.sh --endpoint VPN_IP_OR_DNS [--domain panel.example.com] [--password-file /root/password]"
}
while (($#)); do
  case "$1" in
    --endpoint|--domain|--password-file)
      (($# >= 2)) || { usage; exit 2; }
      case "$1" in
        --endpoint) ENDPOINT=$2;;
        --domain) DOMAIN=$2;;
        --password-file) PASSWORD_FILE=$2;;
      esac
      shift 2;;
    --help|-h) usage; exit 0;;
    *) usage; exit 2;;
  esac
done
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Only Ubuntu 24.04 is supported.' >&2; exit 1; }
[[ $ENDPOINT =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && ${#ENDPOINT} -le 253 ]] || { usage; exit 2; }
[[ -z $DOMAIN || ( $DOMAIN =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && ${#DOMAIN} -le 253 ) ]] || { echo 'Invalid domain.' >&2; exit 2; }
[[ -c /dev/net/tun ]] || { echo 'TUN is unavailable. Enable it with your VPS provider.' >&2; exit 1; }
[[ ! -e /opt/openvpn-panel && ! -e /etc/openvpn-panel && ! -e /var/lib/openvpn-panel ]] || {
  echo 'Existing or incomplete installation detected; refusing to overwrite keys/data. See docs/OPERATIONS.md.' >&2; exit 1;
}
if find /etc/openvpn -type f \( -name '*.conf' -o -name '*.ovpn' \) -print -quit 2>/dev/null | grep -q .; then
  echo 'Existing OpenVPN configuration detected. Use a new server.' >&2; exit 1
fi
if { [[ -r /etc/ufw/ufw.conf ]] && grep -Eq '^[[:space:]]*ENABLED[[:space:]]*=[[:space:]]*yes([[:space:]]|$)' /etc/ufw/ufw.conf; } || systemctl is-active --quiet firewalld; then
  echo 'Active UFW/firewalld detected. Use a dedicated fresh server; do not disable an existing firewall blindly.' >&2; exit 1
fi
if [[ -n $DOMAIN && -e /etc/caddy/Caddyfile ]]; then
  echo 'Existing Caddy configuration detected; refusing to replace it.' >&2; exit 1
fi
# Prevent overlapping the tunnel subnet with an existing attached network.
python3 - <<'PY'
import ipaddress, json, subprocess
net = ipaddress.ip_network('10.87.0.0/24')
for row in json.loads(subprocess.check_output(['ip', '-j', '-4', 'route'])):
    dst = row.get('dst', 'default')
    if dst != 'default' and net.overlaps(ipaddress.ip_network(dst, strict=False)):
        raise SystemExit('Existing route overlaps VPN subnet 10.87.0.0/24; use a fresh server.')
PY
INTERFACE=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
[[ $INTERFACE =~ ^[A-Za-z0-9_.:-]+$ ]] || { echo 'No IPv4 default-route interface.' >&2; exit 1; }
# Fail early on occupied application ports, without changing firewall rules.
if ss -H -lun 'sport = :1194' | grep -q . || ss -H -ltn 'sport = :8000' | grep -q .; then
  echo 'UDP 1194 or TCP 8000 is already in use.' >&2; exit 1
fi
if [[ -n $DOMAIN ]] && ss -H -ltn '( sport = :80 or sport = :443 )' | grep -q .; then
  echo 'HTTP/HTTPS port already in use.' >&2; exit 1
fi
CADDY_NEW=0
if ! command -v caddy >/dev/null; then
  CADDY_NEW=1
  systemctl mask --runtime caddy.service
fi
trap 'if [[ $CADDY_NEW == 1 ]]; then systemctl unmask --runtime caddy.service >/dev/null 2>&1 || true; fi' EXIT
export DEBIAN_FRONTEND=noninteractive
apt-get update
PACKAGES=(python3 python3-venv openvpn openssl iptables sudo ca-certificates caddy)
apt-get install -y "${PACKAGES[@]}"
getent passwd openvpn-panel >/dev/null || useradd --system --home-dir /var/lib/openvpn-panel --shell /usr/sbin/nologin openvpn-panel
install -d -o root -g root -m 0755 /opt/openvpn-panel
# Copy only known application files, not .git, credentials, test databases or venv.
for file in app.py quota.py hook_entry.py collector_entry.py broker_entry.py scheduler_entry.py metrics.py requirements.txt; do
  install -m 0644 "$SOURCE/$file" /opt/openvpn-panel/
done
for dir in vpn templates static; do
  cp -r "$SOURCE/$dir" /opt/openvpn-panel/
done
chown -R root:root /opt/openvpn-panel
find /opt/openvpn-panel -type d -exec chmod 0755 {} +
find /opt/openvpn-panel -type f -exec chmod 0644 {} +
python3 -m venv /opt/openvpn-panel/.venv
/opt/openvpn-panel/.venv/bin/pip install -r /opt/openvpn-panel/requirements.txt
chmod -R a+rX /opt/openvpn-panel/.venv
install -d -o openvpn-panel -g openvpn-panel -m 0770 /var/lib/openvpn-panel
install -d -o root -g root -m 0700 /var/lib/openvpn-panel-revocations
install -d -o root -g openvpn-panel -m 0710 /var/lib/openvpn-panel-backups /var/lib/openvpn-panel-status
install -d -m 0755 /etc/openvpn/server
/opt/openvpn-panel/.venv/bin/python "$SOURCE/scripts/configure.py" "$ENDPOINT" "$DOMAIN" "$INTERFACE" "$PASSWORD_FILE"
/opt/openvpn-panel/.venv/bin/python -Es -c "import sys; sys.path.insert(0,'/opt/openvpn-panel'); from vpn.network_settings import bootstrap; bootstrap(bool(int(sys.argv[1])))" "$CADDY_NEW"
if [[ $CADDY_NEW == 1 ]]; then
  systemctl unmask --runtime caddy.service
  if [[ -z $DOMAIN ]]; then systemctl disable --now caddy.service; fi
fi
# Make DB before OpenVPN hooks run. All writers use group-compatible journals.
sudo -u openvpn-panel /opt/openvpn-panel/.venv/bin/python -c "import sys; sys.path.insert(0,'/opt/openvpn-panel'); from quota import Quotas; Quotas('/var/lib/openvpn-panel/quota.sqlite')"
chmod 0660 /var/lib/openvpn-panel/quota.sqlite
install -m 0755 "$SOURCE/scripts/panelctl.py" /usr/local/sbin/openvpn-panelctl
install -m 0644 "$SOURCE"/deploy/*.service "$SOURCE"/deploy/*.timer /etc/systemd/system/
install -d /etc/systemd/system/openvpn-server@panel.service.d
install -m 0644 "$SOURCE/deploy/openvpn-override.conf" /etc/systemd/system/openvpn-server@panel.service.d/panel.conf
systemctl daemon-reload
systemctl enable --now openvpn-panel-backup.timer
systemctl enable --now openvpn-panel-network.service openvpn-panel.service openvpn-panel-pki.service
systemctl enable --now openvpn-server@panel.service
if [[ -n $DOMAIN ]]; then
  caddy validate --config /etc/caddy/Caddyfile
  systemctl enable caddy
  systemctl restart caddy
fi
sleep 3
for SERVICE in openvpn-panel-accounting.service openvpn-server@panel.service openvpn-panel.service openvpn-panel-pki.service; do
  systemctl is-active --quiet "$SERVICE"
done
[[ -S /run/openvpn-panel-pki/broker.sock && -f /run/openvpn-panel/heartbeat ]] || {
  echo 'Required broker/heartbeat not ready; inspect systemd journals.' >&2; exit 1
}
printf '\nInstalled. Allow UDP 1194 in your provider firewall.\n'
if [[ -n $DOMAIN ]]; then
  printf 'Panel: https://%s (DNS must point here; allow TCP 80/443 for HTTPS).\n' "$DOMAIN"
else
  printf 'On YOUR computer: ssh -N -L 8000:127.0.0.1:8000 root@%s\nThen open http://localhost:8000\n' "$ENDPOINT"
  echo 'Subscription links in SSH mode only work for someone with a tunnel. Use --domain on a new installation for public HTTPS status links.'
fi
