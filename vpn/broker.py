"""Root PKI broker. Only the dedicated panel UID may use the Unix socket."""
import json
import os
from pathlib import Path
import pwd
import socket
import socketserver
import struct
from vpn.provision import profile
from vpn.maintenance import dispatch

SOCKET = '/run/openvpn-panel-pki/broker.sock'


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        _, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != self.server.allowed_uid:
            return
        try:
            line = self.rfile.readline(16385)
            if len(line) > 16384 or not line.endswith(b'\n'):
                return
            message = json.loads(line)
            if type(message) is not dict:
                raise ValueError('invalid request')
            if 'operation' in message:
                result = dict(ok=True, result=dispatch(message))
            else:
                if set(message) != {'name', 'action'} or not all(type(v) is str for v in message.values()):
                    raise ValueError('invalid request')
                result = dict(ok=True, profile=profile(message['name'], message['action']))
        except Exception:
            # No certificate material or request bodies in journal.
            print('PKI request failed', flush=True)
            result = dict(ok=False)
        try:
            self.wfile.write(json.dumps(result).encode() + b'\n')
        except OSError:
            pass


def main():
    os.umask(0o077)
    Path(SOCKET).unlink(missing_ok=True)
    with socketserver.UnixStreamServer(SOCKET, Handler) as server:
        server.allowed_uid = pwd.getpwnam('openvpn-panel').pw_uid
        os.chmod(SOCKET, 0o660)
        server.serve_forever()


if __name__ == '__main__':
    main()
