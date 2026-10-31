import os
from pathlib import Path
import tempfile
import socket
import time
import unittest
from unittest.mock import Mock, patch
from quota import Quotas
from vpn.collector import parse_status, enforce, Management, notify
from vpn.hook import run, address

STATUS = '''TITLE\tOpenVPN 2.6
TIME\t2026-10-31\t1793440000
HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID
CLIENT_LIST\talice\t192.0.2.10:54321\t10.87.0.2\t100\t200\ttoday\t1000\tUNDEF\t0\t0
HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref
GLOBAL_STATS\tMax bcast/mcast queue length\t0
END
'''


class VPNTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.q = Quotas(os.path.join(self.temp.name, 'db.sqlite'))
        self.q.create_user('alice', 1000, 2)
        self.heartbeat = Path(self.temp.name) / 'heartbeat'
        self.heartbeat.touch()
        self.env = dict(common_name='alice', trusted_ip='192.0.2.10', trusted_port='54321')

    def tearDown(self):
        self.temp.cleanup()

    def test_status_parser(self):
        self.assertEqual(parse_status(STATUS), [('alice', '192.0.2.10:54321', 100, 200)])
        for text in [STATUS.replace('END', ''), 'END', STATUS.replace('100\t200', '-1\t200'),
                     STATUS.replace('CLIENT_LIST\talice', 'CLIENT_LIST\tbad\nname')]:
            with self.assertRaises((ValueError, KeyError)):
                parse_status(text)

    def test_hook_first_connection_and_single_session(self):
        run('connect', self.env, self.q, self.heartbeat)
        self.assertIsNotNone(self.q.status('alice').first_connected)
        with self.assertRaises(PermissionError):
            run('connect', self.env, self.q, self.heartbeat)
        run('disconnect', dict(self.env, bytes_received='100', bytes_sent='300'), self.q)
        self.assertEqual(self.q.status('alice').used_bytes, 400)
        run('connect', self.env, self.q, self.heartbeat)
        self.q.vpn_account('alice', address(self.env), 10, 20)
        self.assertEqual(self.q.status('alice').used_bytes, 430)

    def test_heartbeat_fail_closed(self):
        os.utime(self.heartbeat, (time.time()-20, time.time()-20))
        with self.assertRaises(PermissionError):
            run('connect', self.env, self.q, self.heartbeat)
        self.heartbeat.unlink()
        with self.assertRaises(FileNotFoundError):
            run('connect', self.env, self.q, self.heartbeat)
        self.assertIsNone(self.q.status('alice').first_connected)

    def test_live_volume_disable_and_expiry_enforced(self):
        self.q.vpn_connect('alice', '192.0.2.10:54321')
        management = Mock()
        management.status.return_value = parse_status(STATUS)
        enforce(self.q, management)
        management.kill.assert_not_called()
        self.assertEqual(self.q.status('alice').used_bytes, 300)
        self.q.update_limits('alice', 300, 2)
        enforce(self.q, management)
        management.kill.assert_called_with('alice')
        self.q.update_limits('alice', 1000, 2)
        self.q.set_enabled('alice', False)
        enforce(self.q, management)
        self.assertEqual(management.kill.call_count, 2)
        self.q.set_enabled('alice', True)
        with self.q._db() as db:
            db.execute('UPDATE users SET first_connected=1')
        enforce(self.q, management)
        self.assertEqual(management.kill.call_count, 3)

    def test_snapshot_disconnect_race(self):
        self.q.vpn_connect('alice', address(self.env))
        self.q.vpn_account('alice', address(self.env), 200, 300, final=True)
        self.q.vpn_account('alice', address(self.env), 100, 200)
        self.assertEqual(self.q.status('alice').used_bytes, 500)

    def test_unknown_session_killed_and_reset(self):
        management = Mock()
        management.status.return_value = parse_status(STATUS)
        enforce(self.q, management)
        management.kill.assert_called_once_with('alice')
        self.q.vpn_connect('alice', address(self.env))
        self.q.reset_sessions()
        self.q.vpn_connect('alice', address(self.env))

    def test_limits_preserve_usage_and_first_connection(self):
        self.q.vpn_connect('alice', address(self.env), now=100)
        self.q.vpn_account('alice', address(self.env), 10, 20)
        self.q.update_limits('alice', 5000, 30)
        self.assertEqual(self.q.status('alice').used_bytes, 30)
        self.assertEqual(self.q.status('alice').first_connected, 100)
        for volume, days in [(0, 1), (1, 0), (2**70, 1), (1, 10000)]:
            with self.assertRaises(ValueError):
                self.q.update_limits('alice', volume, days)

    def test_rotation_marker_denies_admission(self):
        (self.heartbeat.parent / 'revoke-alice').touch()
        with patch('vpn.hook.REVOCATIONS', self.heartbeat.parent), self.assertRaises(PermissionError):
            run('connect', self.env, self.q, self.heartbeat)

    def test_ipv6_address_matches_management(self):
        self.assertEqual(address(dict(trusted_ip6='2001:db8::1', trusted_port='1234')), '[2001:db8::1]:1234')

    def test_systemd_watchdog_notification(self):
        path = str(Path(self.temp.name) / 'notify.sock')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
            receiver.bind(path)
            receiver.settimeout(1)
            with patch.dict(os.environ, {'NOTIFY_SOCKET': path}):
                notify('READY=1\nWATCHDOG=1')
            self.assertEqual(receiver.recv(1024), b'READY=1\nWATCHDOG=1')
