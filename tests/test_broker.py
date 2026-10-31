import json
import os
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch
from vpn.broker import Handler
from vpn.client import request_profile
from vpn.provision import profile


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'broker.sock')
        self.server = socketserver.UnixStreamServer(self.path, Handler)
        self.server.allowed_uid = os.getuid()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.temp.cleanup()

    def test_authorized_round_trip(self):
        with patch('vpn.broker.profile', return_value='client\n<key>secret</key>') as make:
            self.assertEqual(request_profile('alice', 'download', self.path), 'client\n<key>secret</key>')
            make.assert_called_once_with('alice', 'download')

    def test_wrong_uid_rejected(self):
        self.server.allowed_uid = os.getuid() + 1
        with self.assertRaises((OSError, ValueError)):
            request_profile('alice', 'download', self.path)

    def test_helper_failure_not_exposed(self):
        with patch('vpn.broker.profile', side_effect=ValueError('private-secret')):
            with self.assertRaisesRegex(ValueError, '^profile unavailable$'):
                request_profile('alice', 'download', self.path)

    def test_extra_fields_rejected(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(self.path)
            connection.sendall(b'{"name":"alice","action":"download","command":"rm"}\n')
            self.assertEqual(json.loads(connection.recv(1024)), {'ok': False})

    def test_provision_rejects_injection_before_accessing_pki(self):
        for name in ('../root', 'alice\nremote evil 1', 'a;id', 'a/b', 'a' * 65):
            with self.assertRaises(ValueError):
                profile(name)
        with self.assertRaises(ValueError):
            profile('alice', 'shell')
