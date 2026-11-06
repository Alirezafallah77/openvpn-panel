"""Root-only management socket poller; systemd BindsTo stops VPN on failure."""
import os
import json
import re
import socket
import time
from pathlib import Path
from quota import Quotas

SOCKET = '/run/openvpn-panel/management.sock'
HEARTBEAT = '/run/openvpn-panel/heartbeat'
REVOCATIONS = Path('/var/lib/openvpn-panel-revocations')
SNAPSHOT = Path('/var/lib/openvpn-panel-status/online.json')
NAME = re.compile(r'[A-Za-z0-9_-]{1,64}\Z', re.ASCII)


def parse_status(text, *, include_ids=False):
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
            entry=(name,row['Real Address'],rx,tx)
            if include_ids:
                cid=row['Client ID']
                if not cid.isascii() or not cid.isdigit() or not 0 <= int(cid) < 2**64:
                    raise ValueError('invalid client id')
                entry += (int(cid),)
            clients.append(entry)
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
                return parse_status('\n'.join(lines),include_ids=True)
        raise ValueError('oversized status')

    def kill(self, name):
        if not NAME.fullmatch(name):
            raise ValueError('invalid name')
        self._kill_command(f'kill {name}\n')

    def kill_client(self, client_id):
        if type(client_id) is not int or not 0 <= client_id < 2**64:
            raise ValueError('invalid client id')
        self._kill_command(f'client-kill {client_id}\n')

    def _kill_command(self, command):
        self.sock.sendall(command.encode('ascii'))
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
    online = []
    for entry in management.status():
        name,address,rx,tx=entry[:4]
        # With duplicate-cn a name-based kill also disconnects valid siblings.
        # The root management Client ID isolates the rejected transport.
        def disconnect():
            if len(entry)==5: management.kill_client(entry[4])
            else: management.kill(name)  # Legacy/test adapter; production uses IDs.
        try:
            state = quotas.vpn_account(name, address, rx, tx)
        except KeyError:
            disconnect()  # Unknown certificates/sessions never get free traffic.
            continue
        if not state.allowed or (REVOCATIONS / ('revoke-' + name)).exists():
            disconnect()
        else:
            online.append(name)
    return online


def notify(message):
    """Minimal sd_notify; watchdog also catches an alive but stalled collector."""
    destination = os.environ.get('NOTIFY_SOCKET')
    if not destination:
        return
    if destination.startswith('@'):
        destination = '\0' + destination[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.sendto(message.encode('ascii'), destination)


def main():
    os.umask(0o007)
    quotas = Quotas('/var/lib/openvpn-panel/quota.sqlite')
    # READY must precede OpenVPN startup, otherwise dependency ordering deadlocks.
    notify('READY=1\nWATCHDOG=1')
    # On startup allow OpenVPN time to create its socket. No admission before heartbeat.
    started = time.monotonic()
    while not Path(SOCKET).exists():
        if time.monotonic() - started > 45:
            raise TimeoutError('OpenVPN management socket not available')
        notify('WATCHDOG=1')
        time.sleep(0.2)
    management = Management()
    try:
        while True:
            online = enforce(quotas, management)
            # A second snapshot ensures the killed connection is absent before
            # admitting the replacement certificate with the same common name.
            pending = list(REVOCATIONS.glob('revoke-*'))
            if pending:
                live = {row[0] for row in management.status()}
                for marker in pending:
                    if marker.name[7:] not in live:
                        marker.unlink(missing_ok=True)
            temporary = SNAPSHOT.with_suffix('.new')
            temporary.write_text(json.dumps(dict(updated_at=time.time(), users=online)))
            temporary.chmod(0o640)
            temporary.replace(SNAPSHOT)
            Path(HEARTBEAT).touch(mode=0o600)
            notify('WATCHDOG=1')
            time.sleep(2)
    finally:
        management.close()


if __name__ == '__main__':
    main()
