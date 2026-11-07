import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from vpn import maintenance as m


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.directory = self.root / 'files'
        self.directory.mkdir()
        (self.root/'pki').mkdir()
        self.patches = [patch.object(m, 'ROOT', self.root), patch.object(m, 'DIRECTORY', self.directory)]
        for p in self.patches: p.start()
        self.message = dict(operation='backup-settings-save', enabled=True, interval=15,
            token='12345678:'+'a'*32, chat_id='-100123456789', passphrase='correct-backup-passphrase')

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def test_masked_settings_blank_preserves_secrets(self):
        public = m.save_settings(self.message)
        encoded = json.dumps(public)
        self.assertNotIn(self.message['token'], encoded)
        self.assertNotIn(self.message['passphrase'], encoded)
        self.assertTrue(public['token_configured'])
        self.assertEqual((self.root/'telegram.json').stat().st_mode & 0o777, 0o600)
        m.save_settings(dict(self.message, interval=30, token='', passphrase=''))
        self.assertEqual(m.settings()['token'], self.message['token'])
        self.assertEqual(m.settings()['interval'], 30)

    def test_invalid_parameters_rejected(self):
        for changes in (dict(interval=0), dict(interval=True), dict(token='token\nheader'),
                        dict(chat_id='../../evil')):
            with self.assertRaises(ValueError): m.save_settings(dict(self.message, **changes))
        with self.assertRaises(ValueError): m.dispatch(dict(operation='web-control', action='reboot'))
        with self.assertRaises(ValueError): m.dispatch(dict(operation='shell', command='id'))

    def test_interval_retention_and_telegram_failure(self):
        m.save_settings(self.message)
        with patch('vpn.maintenance.backups.capture', return_value=b'test archive'), patch.object(m, 'send_telegram') as send:
            result = m.run_backup()
            send.assert_called_once()
            self.assertEqual(len(m.files()), 1)
            self.assertTrue((self.directory/m.files()[0]['name']).read_bytes() == b'test archive')
            self.assertIsNone(m.run_backup())
            with patch.object(m, 'send_telegram', side_effect=OSError('bot-secret-must-not-leak')):
                result = m.run_backup(manual=True)
            self.assertEqual(result['state']['last_error'], 'telegram_failed')
            self.assertNotIn('bot-secret', json.dumps(result))
        for number in range(25):
            name = f'backup-20000101T000000Z-{number:08x}.ovpnbak'
            (self.directory/name).write_bytes(b'old')
        with patch('vpn.maintenance.backups.capture', return_value=b'test archive'):
            target = m.create_backup(m.settings())
        self.assertTrue(target.exists())
        self.assertEqual(len(list(self.directory.glob('*.ovpnbak'))), 20)

    def test_disabled_scheduler_and_backup_failure(self):
        self.assertIsNone(m.run_backup())
        result = m.run_backup(manual=True)
        self.assertEqual(result['state']['last_error'], 'backup_failed')

    def test_fixed_service_control_only(self):
        with patch.object(m.subprocess, 'run') as run:
            self.assertEqual(m.control_web('stop'), {'scheduled':True})
            arguments = run.call_args.args[0]
            self.assertEqual(arguments[-2:], ['/usr/local/sbin/openvpn-panelctl','web-stop'])
        with self.assertRaises(ValueError): m.control_web('restart; id')

    def test_telegram_transport_accepts_bounded_plain_and_legacy_archives(self):
        path = self.directory/'backup-20261031T000000Z-abcdef12.ovpnbak'
        path.write_bytes(b'plain private archive')
        with self.assertRaises(ValueError):
            m.send_telegram(self.message['token'],self.message['chat_id'],path)
        path.write_bytes(b'\x1f\x8btest archive')
        from unittest.mock import MagicMock
        response = MagicMock()
        response.read.return_value = b'{"ok":true}'
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            m.send_telegram(self.message['token'],self.message['chat_id'],path)
        request = opener.open.call_args.args[0]
        self.assertTrue(request.full_url.startswith('https://api.telegram.org/bot'))
        self.assertIn(b'\x1f\x8btest archive', request.data)
        self.assertIn(b'multipart/form-data', request.headers['Content-type'].encode())
        response.read.return_value = b'{"ok":false}'
        with patch.object(m.urllib.request, 'build_opener', return_value=opener), self.assertRaises(ValueError):
            m.send_telegram(self.message['token'],self.message['chat_id'],path)

    def test_manual_send_is_independent_of_scheduler_and_preserves_local_backup(self):
        m.save_settings(dict(self.message,enabled=False))
        with patch('vpn.maintenance.backups.capture',return_value=b'test archive'), patch.object(m,'send_telegram') as send:
            local=m.run_backup(manual=True)
            self.assertEqual(local['state']['telegram_status'],'skipped')
            send.assert_not_called()
            sent=m.dispatch(dict(operation='backup-create',send_now=True))
            send.assert_called_once()
            self.assertEqual(sent['state']['telegram_status'],'sent')
            self.assertTrue(sent['state']['last_sent'])
            self.assertFalse(sent['enabled'])
            self.assertIsNone(m.run_backup())
            with patch.object(m,'send_telegram',side_effect=m.TelegramFailure('chat_not_found')):
                failed=m.run_backup(manual=True,send_now=True)
            self.assertEqual(failed['state']['telegram_error'],'chat_not_found')
            self.assertEqual(failed['state']['last_error'],'telegram_failed')
            self.assertTrue((self.directory/failed['state']['filename']).exists())
        for value in ('yes',1,None):
            with self.assertRaises(ValueError): m.dispatch(dict(operation='backup-create',send_now=value))

    def test_manual_send_without_config_does_not_attempt_network(self):
        with patch('vpn.maintenance.backups.capture',return_value=b'test archive'),patch.object(m,'send_telegram') as send:
            result=m.run_backup(manual=True,send_now=True)
        send.assert_not_called()
        self.assertEqual(result['state']['telegram_error'],'not_configured')
        self.assertEqual(result['state']['telegram_status'],'failed')
        self.assertTrue((self.directory/result['state']['filename']).exists())

    def test_telegram_api_error_classification_and_secret_redaction(self):
        import io
        from unittest.mock import MagicMock
        cases=[(401,'TOKEN_SECRET','invalid_token'),(404,'not found','invalid_token'),
            (400,'Bad Request: chat not found TOKEN_SECRET','chat_not_found'),
            (400,'group migrated to supergroup','chat_migrated'),
            (400,'not enough rights to send documents','permission_denied'),
            (403,'Forbidden: bot was blocked by the user','bot_blocked'),
            (403,'Forbidden: bot is not a member','permission_denied'),
            (429,'Too Many Requests','rate_limited'),(500,'server problem','telegram_unavailable'),
            (413,'file too big','file_too_large'),(400,'other private response','invalid_request')]
        path=self.directory/'backup-20261031T000000Z-abcdef12.ovpnbak'
        path.write_bytes(b'\x1f\x8btest archive')
        for status,description,expected in cases:
            raw=json.dumps(dict(ok=False,description=description,parameters={'retry_after':12})).encode()
            error=m.urllib.error.HTTPError('https://api.telegram.org/botTOKEN_SECRET/sendDocument',status,'TOKEN_SECRET',{},io.BytesIO(raw))
            opener=MagicMock();opener.open.side_effect=error
            with patch.object(m.urllib.request,'build_opener',return_value=opener):
                with self.assertRaises(m.TelegramFailure) as raised:
                    m.send_telegram(self.message['token'],self.message['chat_id'],path)
            self.assertEqual(raised.exception.code,expected)
            self.assertNotIn('TOKEN_SECRET',str(raised.exception))
            if status==429: self.assertEqual(raised.exception.retry_after,12)
        # Only an allowlisted classification, never arbitrary API descriptions,
        # request URLs or credentials may reach state.json and the web response.
        m.save_settings(self.message)
        with patch('vpn.maintenance.backups.capture',return_value=b'archive'),patch.object(m,'send_telegram',side_effect=m.TelegramFailure('invalid_token')):
            result=m.run_backup(manual=True)
        encoded=json.dumps(result)
        self.assertNotIn(self.message['token'],encoded)
        self.assertNotIn('TOKEN_SECRET',encoded)

    def test_telegram_network_tls_timeout_and_invalid_response(self):
        from unittest.mock import MagicMock
        path=self.directory/'backup-20261031T000000Z-abcdef12.ovpnbak'
        path.write_bytes(b'\x1f\x8btest archive')
        errors=[(m.urllib.error.URLError(m.socket.gaierror('SECRET')),'dns_error'),
            (m.urllib.error.URLError(m.ssl.SSLCertVerificationError('SECRET')),'tls_error'),
            (m.urllib.error.URLError(TimeoutError('SECRET')),'timeout'),
            (TimeoutError('SECRET'),'timeout'),(OSError('SECRET'),'network_error')]
        for error,code in errors:
            opener=MagicMock();opener.open.side_effect=error
            with patch.object(m.urllib.request,'build_opener',return_value=opener):
                with self.assertRaises(m.TelegramFailure) as raised: m.send_telegram(self.message['token'],self.message['chat_id'],path)
            self.assertEqual(raised.exception.code,code)
            self.assertNotIn('SECRET',str(raised.exception))
        for raw in (b'[]',b'not json',b'x'*65537,b'{"ok":false,"error_code":400,"description":"chat not found"}'):
            opener=MagicMock();opener.open.return_value.__enter__.return_value.read.return_value=raw
            with patch.object(m.urllib.request,'build_opener',return_value=opener),self.assertRaises(m.TelegramFailure):
                m.send_telegram(self.message['token'],self.message['chat_id'],path)
