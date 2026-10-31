"""Run by install.sh after dependencies; creates a NEW, dedicated installation."""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

ROOT = Path('/etc/openvpn-panel')
APP = Path('/opt/openvpn-panel')


def cmd(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def write(path, text, mode=0o600):
    path = Path(path)
    path.write_text(text)
    path.chmod(mode)


def main():
    endpoint, domain, interface, password_file = sys.argv[1:]
    # Strict endpoint validation also protects generated OpenVPN / Caddy syntax.
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', endpoint):
        raise ValueError('endpoint must be IPv4 or a DNS name')
    if domain and not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', domain):
        raise ValueError('invalid panel domain')
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', interface):
        raise ValueError('invalid network interface')
    os.umask(0o077)
    # Validate password before making PKI/data changes.
    from werkzeug.security import generate_password_hash
    import getpass
    if password_file:
        import stat
        password_path = Path(password_file)
        info = password_path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('password file must be root-owned, regular, mode 0600')
        password = password_path.read_text().rstrip('\r\n')
        if len(password) < 12 or '\n' in password:
            raise ValueError('password needs 12+ characters on one line')
    else:
        while True:
            password = getpass.getpass('Admin password (minimum 12 characters): ')
            confirm = getpass.getpass('Repeat password: ')
            if len(password) >= 12 and password == confirm:
                break
            print('Passwords must match and be at least 12 characters.')
    ROOT.mkdir(mode=0o700)
    pki = ROOT / 'pki'
    pki.mkdir(mode=0o700)
    (pki / 'newcerts').mkdir()
    write(pki / 'index.txt', '')
    write(pki / 'index.txt.attr', 'unique_subject = no\n')
    write(pki / 'serial', '1000\n')
    write(pki / 'crlnumber', '1000\n')
    write(pki / 'openssl.cnf', f'''[ ca ]
default_ca = panel_ca
[ panel_ca ]
dir = {pki}
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/ca.crt
private_key = $dir/ca.key
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_days = 3650
default_crl_days = 3650
policy = policy
unique_subject = no
[ policy ]
commonName = supplied
[ client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
''')
    cmd('openssl', 'req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
        '-nodes', '-keyout', str(pki / 'ca.key'), '-out', str(pki / 'ca.crt'), '-days', '3650',
        '-subj', '/CN=OpenVPN Panel CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    cmd('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
        '-nodes', '-keyout', str(pki / 'server.key'), '-out', str(pki / 'server.csr'),
        '-subj', '/CN=ovp-panel-server')
    cmd('openssl', 'ca', '-batch', '-notext', '-config', str(pki / 'openssl.cnf'),
        '-extensions', 'server_cert', '-in', str(pki / 'server.csr'), '-out', str(pki / 'server.crt'))
    cmd('openssl', 'ca', '-batch', '-config', str(pki / 'openssl.cnf'), '-gencrl', '-out', str(ROOT / 'crl.pem'))
    cmd('openvpn', '--genkey', 'secret', str(ROOT / 'tls-crypt.key'))
    write(ROOT / 'vpn.json', json.dumps(dict(endpoint=endpoint, port=1194)))
    write('/etc/openvpn/server/panel.conf', f'''port 1194
proto udp4
dev tun-panel
dev-type tun
topology subnet
server 10.87.0.0 255.255.255.0
server-ipv6 fd42:87:87::/64
block-ipv6
ca {pki}/ca.crt
cert {pki}/server.crt
key {pki}/server.key
dh none
crl-verify {ROOT}/crl.pem
tls-crypt {ROOT}/tls-crypt.key
tls-version-min 1.2
remote-cert-tls client
verify-client-cert require
allow-compression no
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
keepalive 10 60
persist-key
persist-tun
script-security 2
client-connect "/usr/local/sbin/openvpn-panel-hook connect"
client-disconnect "/usr/local/sbin/openvpn-panel-hook disconnect"
management /run/openvpn-panel/management.sock unix
status-version 3
max-clients 200
push "redirect-gateway def1 ipv6 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 9.9.9.9"
push "block-ipv6"
verb 3
''')
    write('/usr/local/sbin/openvpn-panel-hook', '#!/bin/sh\nexec /opt/openvpn-panel/.venv/bin/python -Es /opt/openvpn-panel/hook_entry.py "$@"\n', 0o755)
    write('/usr/local/sbin/openvpn-panel-profile', '#!/bin/sh\nexec /opt/openvpn-panel/.venv/bin/python -I /opt/openvpn-panel/vpn/provision.py "$@"\n', 0o755)
    write('/etc/sudoers.d/openvpn-panel', 'Defaults:openvpn-panel !requiretty\nopenvpn-panel ALL=(root) NOPASSWD: /usr/local/sbin/openvpn-panel-profile *\n', 0o440)
    cmd('visudo', '-cf', '/etc/sudoers.d/openvpn-panel')
    # Independent chains; no flush of host firewall and no INPUT/SSH policy changes.
    write('/usr/local/sbin/openvpn-panel-network', f'''#!/bin/bash
set -euo pipefail
IPT=/usr/sbin/iptables
if [[ ${{1:-}} == start ]]; then
  $IPT -w -N OVP_PANEL_FWD 2>/dev/null || true
  $IPT -w -F OVP_PANEL_FWD
  for NET in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    $IPT -w -A OVP_PANEL_FWD -i tun-panel -d "$NET" -j DROP
  done
  $IPT -w -A OVP_PANEL_FWD -i tun-panel -s 10.87.0.0/24 -o {interface} -j ACCEPT
  $IPT -w -A OVP_PANEL_FWD -i {interface} -o tun-panel -d 10.87.0.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $IPT -w -A OVP_PANEL_FWD -i tun-panel -j DROP
  $IPT -w -A OVP_PANEL_FWD -o tun-panel -j DROP
  $IPT -w -C FORWARD -j OVP_PANEL_FWD 2>/dev/null || $IPT -w -I FORWARD 1 -j OVP_PANEL_FWD
  $IPT -w -t nat -C POSTROUTING -s 10.87.0.0/24 -o {interface} -j MASQUERADE 2>/dev/null || $IPT -w -t nat -A POSTROUTING -s 10.87.0.0/24 -o {interface} -j MASQUERADE
  $IPT -w -C INPUT -i tun-panel -j DROP 2>/dev/null || $IPT -w -I INPUT 1 -i tun-panel -j DROP
  /usr/sbin/ip6tables -w -C INPUT -i tun-panel -j DROP 2>/dev/null || /usr/sbin/ip6tables -w -I INPUT 1 -i tun-panel -j DROP
  /usr/sbin/ip6tables -w -C FORWARD -i tun-panel -j DROP 2>/dev/null || /usr/sbin/ip6tables -w -I FORWARD 1 -i tun-panel -j DROP
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
elif [[ ${{1:-}} == stop ]]; then
  $IPT -w -D INPUT -i tun-panel -j DROP 2>/dev/null || true
  /usr/sbin/ip6tables -w -D INPUT -i tun-panel -j DROP 2>/dev/null || true
  /usr/sbin/ip6tables -w -D FORWARD -i tun-panel -j DROP 2>/dev/null || true
  $IPT -w -D FORWARD -j OVP_PANEL_FWD 2>/dev/null || true
  $IPT -w -F OVP_PANEL_FWD 2>/dev/null || true
  $IPT -w -X OVP_PANEL_FWD 2>/dev/null || true
  $IPT -w -t nat -D POSTROUTING -s 10.87.0.0/24 -o {interface} -j MASQUERADE 2>/dev/null || true
else
  exit 2
fi
''', 0o755)
    write('/etc/sysctl.d/70-openvpn-panel.conf', 'net.ipv4.ip_forward=1\n', 0o644)
    host = domain or 'localhost'
    env = f'''PANEL_SECRET={secrets.token_urlsafe(48)}
PANEL_PASSWORD_HASH='{generate_password_hash(password)}'
PANEL_DATABASE=/var/lib/openvpn-panel/quota.sqlite
PANEL_HOST={host}
PANEL_VPN_CONFIGURED=1
'''
    if not domain:
        env += 'PANEL_LOCAL_HTTP=1\n'
    write(ROOT / 'panel.env', env)
    if domain:
        write('/etc/caddy/Caddyfile', f'''{domain} {{
    reverse_proxy 127.0.0.1:8000
    # Access logging is intentionally not enabled (subscription tokens).
}}
''', 0o644)


if __name__ == '__main__':
    main()
