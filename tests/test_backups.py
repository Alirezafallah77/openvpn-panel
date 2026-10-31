import io
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock
from quota import Quotas
from vpn import backups


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / 'source'
        pki = self.root / 'pki'
        pki.mkdir(parents=True)
        (pki / 'newcerts').mkdir()
        for file, data in {'index.txt':'', 'serial':'1000\n', 'crlnumber':'1000\n',
                           'openssl.cnf':f'''[ca]
default_ca=CA
[CA]
dir={pki}
database=$dir/index.txt
new_certs_dir=$dir/newcerts
certificate=$dir/ca.crt
private_key=$dir/ca.key
serial=$dir/serial
crlnumber=$dir/crlnumber
default_md=sha256
default_crl_days=365
'''} .items():
            (pki / file).write_text(data)
        def command(*args):
            subprocess.run(['openssl', *args], check=True, capture_output=True)
        command('req','-new','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
                '-nodes','-keyout',str(pki/'ca.key'),'-out',str(pki/'ca.crt'),'-days','365',
                '-subj','/CN=Backup Test CA','-addext','basicConstraints=critical,CA:TRUE')
        command('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
                '-keyout',str(pki/'server.key'),'-out',str(pki/'server.csr'),'-subj','/CN=ovp-panel-server')
        command('x509','-req','-in',str(pki/'server.csr'),'-CA',str(pki/'ca.crt'),'-CAkey',str(pki/'ca.key'),
                '-set_serial','10','-out',str(pki/'server.crt'),'-days','365')
        command('ca','-batch','-config',str(pki/'openssl.cnf'),'-gencrl','-out',str(self.root/'crl.pem'))
        (self.root/'tls-crypt.key').write_text('-----BEGIN OpenVPN Static key V1-----\n'+'ab'*256+'\n-----END OpenVPN Static key V1-----\n')
        (self.root/'panel.env').write_text('OLD_ADMIN_SECRET=must-not-migrate')
        self.db = self.base / 'source.sqlite'
        self.q = Quotas(str(self.db))
        self.token = self.q.create_user('alice', 10000, 30)
        self.q.connect('alice', 'old-server', now=100)
        self.q.account('old-server', 100, 200)
        self.archive = backups.capture(self.root, self.db)

    def tearDown(self):
        self.temp.cleanup()

    def stage(self, data=None):
        stage = self.base / 'stage'
        stage.mkdir(exist_ok=True)
        backups.validate_archive(self.archive if data is None else data, stage)
        return stage

    def target(self):
        root = self.base / 'new-server'
        shutil.copytree(self.root, root)
        (root/'panel.env').write_text('NEW_ADMIN_SECRET=preserved')
        (root/'vpn.json').write_text('{"endpoint":"new.example.com"}')
        (root/'pki/openssl.cnf').write_text('# trusted new server config\n')
        db = self.base / 'new.sqlite'
        Quotas(str(db)).create_user('new-user', 2000, 5)
        return root, db

    def test_authenticated_encryption_and_tamper_detection(self):
        password = 'correct-migration-passphrase'
        encrypted = backups.encrypt(self.archive, password)
        self.assertNotIn(b'BEGIN PRIVATE KEY', encrypted)
        self.assertEqual(backups.decrypt(encrypted, password), self.archive)
        with self.assertRaises(ValueError):
            backups.decrypt(encrypted, 'wrong-password-long-enough')
        damaged = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        with self.assertRaises(ValueError):
            backups.decrypt(damaged, password)
        with self.assertRaises(ValueError):
            backups.encrypt(self.archive, 'short')

    def test_migration_preserves_users_keys_tokens_not_new_host_settings(self):
        stage = self.stage()
        root, db = self.target()
        activate = Mock()
        backups.apply_restore(stage, root, db, activate=activate)
        activate.assert_called_once()
        restored = Quotas(str(db))
        self.assertEqual(restored.status_by_token(self.token).name, 'alice')
        self.assertEqual(restored.status('alice').used_bytes, 300)
        self.assertEqual(restored.status('alice').first_connected, 100)
        with sqlite3.connect(db) as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM sessions WHERE closed=0').fetchone()[0], 0)
        self.assertEqual((root/'pki/ca.key').read_bytes(), (self.root/'pki/ca.key').read_bytes())
        self.assertIn('NEW_ADMIN_SECRET', (root/'panel.env').read_text())
        self.assertIn('new.example.com', (root/'vpn.json').read_text())
        self.assertEqual((root/'pki/openssl.cnf').read_text(), '# trusted new server config\n')

    def test_failed_activation_rolls_back(self):
        stage = self.stage()
        root, db = self.target()
        original = db.read_bytes()
        deactivate = Mock()
        with self.assertRaises(RuntimeError):
            backups.apply_restore(stage, root, db, activate=Mock(side_effect=RuntimeError('start failed')), deactivate=deactivate)
        self.assertEqual(db.read_bytes(), original)
        self.assertEqual(Quotas(str(db)).list_users()[0].name, 'new-user')
        deactivate.assert_called_once()

    def test_reject_path_escape_symlink_duplicate_and_unknown_files(self):
        for name, kind in [('../escape', 'file'), ('/etc/passwd', 'file'),
                           ('etc/openvpn-panel/pki/key', 'symlink'), ('unexpected', 'file'),
                           ('manifest.json', 'duplicate')]:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w:gz') as tar:
                item = tarfile.TarInfo(name)
                if kind == 'symlink':
                    item.type, item.linkname = tarfile.SYMTYPE, '/etc/passwd'
                    tar.addfile(item)
                else:
                    item.size = 2
                    tar.addfile(item, io.BytesIO(b'{}'))
                    if kind == 'duplicate':
                        tar.addfile(item, io.BytesIO(b'{}'))
            with tempfile.TemporaryDirectory() as temp:
                with self.assertRaises(ValueError):
                    backups.validate_archive(stream.getvalue(), Path(temp))

    def test_capture_excludes_host_and_telegram_secrets(self):
        with tarfile.open(fileobj=io.BytesIO(self.archive), mode='r:gz') as archive:
            self.assertNotIn('etc/openvpn-panel/panel.env', archive.getnames())
        self.stage()

    def test_compressed_output_bound_enforced_during_write(self):
        from unittest.mock import patch
        with patch.object(backups, 'MAX_ARCHIVE', 512):
            buffer = backups.BoundedBuffer()
            buffer.write(b'a'*100)
            with self.assertRaises(ValueError):
                buffer.write(b'b'*300)

    def test_invalid_certificate_rejected_before_apply(self):
        (self.root/'pki/server.key').write_text('not a private key')
        data = backups.capture(self.root, self.db)
        with self.assertRaises(subprocess.CalledProcessError):
            self.stage(data)

    def test_encrypted_links_and_deleted_users_survive_restore(self):
        from quota import link_key_path
        token=self.q.create_user('remembered',10000,30,remember=True)
        self.q.delete_user('alice')
        archive=backups.capture(self.root,self.db)
        stage=self.stage(archive)
        root,db=self.target()
        self.assertFalse(link_key_path(db).exists())
        backups.apply_restore(stage,root,db)
        restored=Quotas(str(db))
        self.assertEqual(restored.remembered_token('remembered'),token)
        self.assertIsNone(restored.status_by_token(self.token))
        self.assertEqual([u.name for u in restored.list_users()],['remembered'])
        self.assertEqual(link_key_path(db).stat().st_mode & 0o077,0)
        with self.assertRaises(KeyError): restored.set_enabled('alice',True)

    def test_failed_restore_rolls_back_subscription_key(self):
        from quota import link_key_path
        token=self.q.create_user('remembered',10000,30,remember=True)
        stage=self.stage(backups.capture(self.root,self.db))
        root,db=self.target()
        existing=Quotas(str(db))
        old_token=existing.rotate_token('new-user',remember=True)
        old_key=link_key_path(db).read_bytes()
        with self.assertRaises(RuntimeError):
            backups.apply_restore(stage,root,db,activate=Mock(side_effect=RuntimeError('failed')))
        self.assertEqual(link_key_path(db).read_bytes(),old_key)
        self.assertEqual(Quotas(str(db)).remembered_token('new-user'),old_token)

    def test_capture_rejects_missing_or_wrong_link_key(self):
        from quota import link_key_path
        from cryptography.fernet import Fernet
        self.q.create_user('remembered',100,30,remember=True)
        path=link_key_path(self.db)
        path.unlink()
        with self.assertRaises(ValueError): backups.capture(self.root,self.db)
        path.write_bytes(Fernet.generate_key())
        path.chmod(0o600)
        with self.assertRaises(ValueError): backups.capture(self.root,self.db)
