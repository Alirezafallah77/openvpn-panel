"""Actual OpenSSL issuance and interruption-recovery tests, no VPN/root required."""
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from quota import Quotas
from vpn.provision import profile, command


class PKITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pki = self.root / 'pki'
        self.pki.mkdir()
        (self.pki / 'newcerts').mkdir()
        self.db = str(self.root / 'db.sqlite')
        Quotas(self.db).create_user('alice', 100, 2)
        self.real_connect = sqlite3.connect
        (self.pki / 'index.txt').write_text('')
        (self.pki / 'serial').write_text('1000\n')
        (self.pki / 'crlnumber').write_text('1000\n')
        (self.pki / 'openssl.cnf').write_text(f'''[ca]
default_ca=CA
[CA]
dir={self.pki}
database=$dir/index.txt
new_certs_dir=$dir/newcerts
certificate=$dir/ca.crt
private_key=$dir/ca.key
serial=$dir/serial
crlnumber=$dir/crlnumber
default_md=sha256
default_days=365
default_crl_days=365
policy=policy
unique_subject=no
[policy]
commonName=supplied
[client_cert]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
''')
        command('openssl', 'req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt',
                'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(self.pki / 'ca.key'),
                '-out', str(self.pki / 'ca.crt'), '-days', '365', '-subj', '/CN=Test CA',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        command('openssl', 'ca', '-batch', '-config', str(self.pki / 'openssl.cnf'),
                '-gencrl', '-out', str(self.root / 'crl.pem'))
        (self.root / 'vpn.json').write_text('{"endpoint":"192.0.2.1","port":1194}')
        (self.root / 'tls-crypt.key').write_text('test-tls-key\n')
        self.revocations = self.root / 'revocations'
        self.revocations.mkdir()
        self.patch_db = patch('vpn.provision.sqlite3.connect', side_effect=lambda *a, **k: self.real_connect(self.db))
        self.patch_db.start()
        self.patch_revocations = patch('vpn.provision.REVOCATIONS', self.revocations)
        self.patch_revocations.start()

    def tearDown(self):
        self.patch_db.stop()
        self.patch_revocations.stop()
        self.temp.cleanup()

    def verify(self, cert):
        return subprocess.run(['openssl', 'verify', '-CAfile', str(self.pki / 'ca.crt'),
            '-CRLfile', str(self.root / 'crl.pem'), '-crl_check', str(cert)], capture_output=True).returncode

    def test_issue_download_and_revoke(self):
        original = profile('alice', root=self.root)
        self.assertIn('remote 192.0.2.1 1194', original)
        self.assertEqual(original, profile('alice', root=self.root))
        self.assertEqual(self.verify(self.pki / 'client-alice.crt'), 0)
        old_cert = self.root / 'old.crt'
        old_cert.write_bytes((self.pki / 'client-alice.crt').read_bytes())
        replacement = profile('alice', 'rotate', self.root)
        self.assertNotEqual(original, replacement)
        self.assertNotEqual(self.verify(old_cert), 0)
        self.assertEqual(self.verify(self.pki / 'client-alice.crt'), 0)
        self.assertTrue((self.revocations / 'revoke-alice').exists())
        with self.assertRaises(ValueError):
            profile('unknown', root=self.root)

    def test_interrupted_crl_update_can_be_retried(self):
        profile('alice', root=self.root)
        old_cert = self.root / 'old.crt'
        old_cert.write_bytes((self.pki / 'client-alice.crt').read_bytes())
        def interrupted(*args):
            if '-gencrl' in args:
                raise OSError('simulated disk error')
            return command(*args)
        with patch('vpn.provision.command', side_effect=interrupted):
            with self.assertRaises(OSError):
                profile('alice', 'rotate', self.root)
        self.assertTrue((self.pki / 'client-alice.rotation-pending').exists())
        profile('alice', root=self.root)
        self.assertFalse((self.pki / 'client-alice.rotation-pending').exists())
        self.assertNotEqual(self.verify(old_cert), 0)
        self.assertEqual(self.verify(self.pki / 'client-alice.crt'), 0)

    def test_profiles_use_configured_dns_and_tcp_client_protocol(self):
        (self.root/'vpn.json').write_text('{"endpoint":"vpn.example.com","port":1194,"protocol":"tcp"}')
        result=profile('alice',root=self.root)
        self.assertIn('proto tcp4-client\n',result)
        self.assertNotIn('explicit-exit-notify',result)
        self.assertIn('remote vpn.example.com 1194\n',result)
        (self.root/'vpn.json').write_text('{"endpoint":"vpn.example.com","port":1194,"protocol":"udp"}')
        result=profile('alice',root=self.root)
        self.assertIn('proto udp4\n',result)
        self.assertIn('explicit-exit-notify 1\n',result)
