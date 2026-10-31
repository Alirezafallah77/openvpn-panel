"""Unprivileged, size-bounded client for the local PKI broker."""
import json
import socket


def request_profile(name, action, path='/run/openvpn-panel-pki/broker.sock'):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(120)
        connection.connect(path)
        connection.sendall(json.dumps(dict(name=name, action=action)).encode() + b'\n')
        with connection.makefile('rb') as stream:
            raw = stream.readline(65537)
        if len(raw) > 65536 or not raw.endswith(b'\n'):
            raise ValueError('invalid broker response')
        result = json.loads(raw)
        if result.get('ok') is not True or not isinstance(result.get('profile'), str):
            raise ValueError('profile unavailable')
        return result['profile']


def maintenance_request(message, path='/run/openvpn-panel-pki/broker.sock'):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(150)
        connection.connect(path)
        connection.sendall(json.dumps(message).encode() + b'\n')
        with connection.makefile('rb') as stream:
            raw = stream.readline(65537)
        if len(raw) > 65536 or not raw.endswith(b'\n'):
            raise ValueError('Invalid maintenance response')
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get('ok') is not True:
            raise ValueError('Maintenance operation failed')
        return result['result']
