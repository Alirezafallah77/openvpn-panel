"""Root-only management socket poller; systemd BindsTo stops VPN on failure."""
import os
import re
import socket
import time
from pathlib import Path
from quota import Quotas

SOCKET = '/run/openvpn-panel/management.sock'
HEARTBEAT = '/run/openvpn-panel/heartbeat'
REVOCATIONS = Path('/var/lib/openvpn-panel-revocations')
NAME = re.compile(r'[A-Za-z0-9_-]{1,64}\Z', re.ASCII)


def parse_status(text):
    """OpenVPN management `status 3`: tab separated, header-name based."""
    lines = text.splitlines()
    if 'END' not in lines:
        raise ValueError('incomplete status')
    header = None
    clients = []
    for line in lines:
        parts = line.split('\t')
        if parts[:2] == ['HEADER', 'CLIENT_LIST']:
            header = parts[2:]
        elif parts[0] == 'CLIENT_LIST':
            if header is None or len(parts[1:]) != len(header):
                raise ValueError('invalid client status')
            row = dict(zip(header, parts[1:]))
            name = row['Common Name']
            if not NAME.fullmatch(name):
                raise ValueError('invalid common name')
            rx, tx = int(row['Bytes Received']), int(row['Bytes Sent'])
            if min(rx, tx) < 0:
                raise ValueError('invalid counters')
            clients.append((name, row['Real Address'], rx, tx))
    if header is None:
        raise ValueError('missing status header')
    return clients


class Management:
    def __init__(self, path=SOCKET):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(path)
        self.stream = self.sock.makefile('rb')
        self._readline()  # management greeting

    def _readline(self):
        line = self.stream.readline(65536)
        if not line or len(line) >= 65536:
            raise ConnectionError('management closed or oversized line')
        return line.decode('utf-8').rstrip('\r\n')

    def status(self):
        self.sock.sendall(b'status 3\n')
        lines = []
        for _ in range(100000):
            line = self._readline()
            if line.startswith('>'):
                continue
            lines.append(line)
            if line == 'END':
                return parse_status('\n'.join(lines))
        raise ValueError('oversized status')

    def kill(self, name):
        if not NAME.fullmatch(name):
            raise ValueError('invalid name')
        self.sock.sendall(f'kill {name}\n'.encode('ascii'))
        for _ in range(100):
            line = self._readline()
            if line.startswith('SUCCESS:'):
                return
            if line.startswith('ERROR:'):
                # A disconnect between the snapshot and kill is normal.
                return
        raise ConnectionError('missing kill response')

    def close(self):
        self.stream.close()
        self.sock.close()


def enforce(quotas, management):
    for name, address, rx, tx in management.status():
        try:
            state = quotas.vpn_account(name, address, rx, tx)
        except KeyError:
            management.kill(name)  # Unknown certificates/sessions never get free traffic.
            continue
        if not state.allowed or (REVOCATIONS / ('revoke-' + name)).exists():
            management.kill(name)


def main():
    os.umask(0o007)
    quotas = Quotas('/var/lib/openvpn-panel/quota.sqlite')
    # On startup allow OpenVPN time to create its socket. No admission before heartbeat.
    started = time.monotonic()
    while not Path(SOCKET).exists():
        if time.monotonic() - started > 45:
            raise TimeoutError('OpenVPN management socket not available')
        time.sleep(0.2)
    management = Management()
    try:
        while True:
            enforce(quotas, management)
            # A second snapshot ensures the killed connection is absent before
            # admitting the replacement certificate with the same common name.
            pending = list(REVOCATIONS.glob('revoke-*'))
            if pending:
                live = {row[0] for row in management.status()}
                for marker in pending:
                    if marker.name[7:] not in live:
                        marker.unlink(missing_ok=True)
            Path(HEARTBEAT).touch(mode=0o600)
            time.sleep(2)
    finally:
        management.close()


if __name__ == '__main__':
    main()
