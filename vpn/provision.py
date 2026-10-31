"""PKI operations for the root broker; fixed paths and validated certificate names.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

ROOT = Path('/etc/openvpn-panel')
REVOCATIONS = Path('/var/lib/openvpn-panel-revocations')


def command(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=60).stdout.decode('ascii')


def profile(name, action='download', root=ROOT):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name, re.ASCII):
        raise ValueError('invalid name')
    if action not in ('download', 'rotate'):
        raise ValueError('invalid action')
    with sqlite3.connect('file:/var/lib/openvpn-panel/quota.sqlite?mode=ro', uri=True) as db:
        if not db.execute('SELECT 1 FROM users WHERE name=?', (name,)).fetchone():
            raise ValueError('unknown user')
    pki = root / 'pki'
    with (pki / 'lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        conf = json.loads((root / 'vpn.json').read_text())
        chosen = conf.get('protocol','udp')
        if chosen not in ('udp','tcp'):
            raise ValueError('invalid protocol')
        transport = 'udp4' if chosen == 'udp' else 'tcp4-client'
        base = pki / ('client-' + name)
        key, csr, cert = (Path(str(base) + ext) for ext in ('.key', '.csr', '.crt'))
        config = str(pki / 'openssl.cnf')
        # A durable intent allows retry after interrupted revocation/CRL updates.
        intent = Path(str(base) + '.rotation-pending')
        if action == 'rotate' and cert.exists():
            intent.touch(mode=0o600)
        if intent.exists():
            if cert.exists():
                try:
                    command('openssl', 'ca', '-batch', '-config', config, '-revoke', str(cert))
                except subprocess.CalledProcessError as error:
                    if b'Already revoked' not in error.stderr:
                        raise
            tmp = root / 'crl.tmp'
            command('openssl', 'ca', '-batch', '-config', config, '-gencrl', '-out', str(tmp))
            tmp.chmod(0o644)
            tmp.replace(root / 'crl.pem')
            pending = REVOCATIONS / ('revoke-' + name)
            pending.touch(mode=0o600)
            cert.unlink(missing_ok=True)
            key.unlink(missing_ok=True)
            intent.unlink()
        if not cert.exists():
            command('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                    '-nodes', '-keyout', str(key), '-out', str(csr), '-subj', '/CN=' + name)
            command('openssl', 'ca', '-batch', '-notext', '-config', config, '-extensions', 'client_cert',
                    '-in', str(csr), '-out', str(cert))
        ca = (pki / 'ca.crt').read_text()
        tls = (root / 'tls-crypt.key').read_text()
        return f'''client
 dev tun
 proto {transport}
 remote {conf['endpoint']} {conf['port']}
 resolv-retry infinite
 nobind
 persist-key
 persist-tun
 remote-cert-tls server
 verify-x509-name ovp-panel-server name
 auth-nocache
 data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
 auth SHA256
 verb 3
<ca>
{ca}</ca>
<cert>
{cert.read_text()}</cert>
<key>
{key.read_text()}</key>
<tls-crypt>
{tls}</tls-crypt>
'''.replace('\n ', '\n')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        if len(sys.argv) != 3:
            raise ValueError('arguments')
        print(profile(sys.argv[2], sys.argv[1]), end='')
    except Exception:
        print('Profile operation failed. Check root-only PKI state.', file=sys.stderr)
        sys.exit(1)
