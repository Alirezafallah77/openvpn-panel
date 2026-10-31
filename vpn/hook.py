"""Invoked synchronously by OpenVPN; admission errors always deny access."""
import ipaddress
import os
import sys
import time
from pathlib import Path
from quota import Quotas

DATABASE = '/var/lib/openvpn-panel/quota.sqlite'
HEARTBEAT = '/run/openvpn-panel/heartbeat'
REVOCATIONS = Path('/var/lib/openvpn-panel-revocations')


def address(env):
    ip = ipaddress.ip_address(env.get('trusted_ip') or env.get('trusted_ip6', ''))
    port = int(env['trusted_port'])
    if not 1 <= port <= 65535:
        raise ValueError('invalid port')
    return f'[{ip}]:{port}' if ip.version == 6 else f'{ip}:{port}'


def run(action, env, quotas, heartbeat=HEARTBEAT):
    if action == 'reset':
        quotas.reset_sessions()
        return
    name = env['common_name']
    peer = address(env)
    if action == 'connect':
        if (REVOCATIONS / ('revoke-' + name)).exists():
            raise PermissionError('credential rotation pending')
        age = time.time() - Path(heartbeat).stat().st_mtime
        if not 0 <= age <= 15:
            raise PermissionError('accounting unavailable')
        quotas.vpn_connect(name, peer)
    elif action == 'disconnect':
        quotas.vpn_account(name, peer, int(env['bytes_received']), int(env['bytes_sent']), final=True)
    else:
        raise ValueError('unknown hook')


if __name__ == '__main__':
    os.umask(0o007)  # Root hook journals must remain readable/writable to panel group.
    try:
        run(sys.argv[1], os.environ, Quotas(DATABASE))
    except Exception:
        # Do not expose env, IP, credentials or certs in logs.
        print('OpenVPN panel hook failed; connection admission denied if connecting', file=sys.stderr)
        sys.exit(1)
