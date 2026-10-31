import os
import tempfile
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from app import create_app


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = generate_password_hash('test-password-123')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app(dict(TESTING=True, SECRET_KEY='x' * 32,
            ADMIN_PASSWORD_HASH=self.password_hash,
            DATABASE=os.path.join(self.temp.name, 'test.sqlite'),
            SESSION_COOKIE_SECURE=False))
        self.client = self.app.test_client()
        self.q = self.app.extensions['quotas']

    def tearDown(self):
        self.temp.cleanup()

    def post(self, path, data=None):
        self.client.get('/login')
        with self.client.session_transaction() as s:
            csrf = s['csrf']
        return self.client.post(path, data=dict(csrf=csrf, **(data or {})))

    def login(self):
        return self.post('/login', dict(password='test-password-123'))

    def test_auth_csrf_and_logout(self):
        self.assertEqual(self.client.get('/').status_code, 302)
        self.assertEqual(self.client.post('/login').status_code, 400)
        self.assertEqual(self.client.post('/login', data={'csrf':'غلط'}).status_code, 400)
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get('/').status_code, 200)
        self.post('/logout')
        self.assertEqual(self.client.get('/').status_code, 302)

    def test_create_rotate_disable(self):
        self.login()
        r = self.post('/users', dict(name='alice', gib='10', days='30'))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.q.status('alice').limit_bytes, 10 * 1024**3)
        self.assertIsNone(self.q.status('alice').first_connected)
        token = self.q.rotate_token('alice')
        self.assertEqual(self.client.get('/s/' + token).status_code, 200)
        self.post('/users/alice/token')
        self.assertEqual(self.client.get('/s/' + token).status_code, 404)
        self.post('/users/alice/toggle', dict(enabled='0'))
        self.assertFalse(self.q.status('alice').allowed)

    def test_invalid_and_duplicate_inputs(self):
        self.login()
        for values in [dict(name='../bad', gib='1', days='1'),
                       dict(name='alice', gib='-1', days='1'),
                       dict(name='alice', gib='1', days='999999999999999999999')]:
            self.assertEqual(self.post('/users', values).status_code, 400)
        valid = dict(name='alice', gib='1', days='1')
        self.assertEqual(self.post('/users', valid).status_code, 200)
        self.assertEqual(self.post('/users', valid).status_code, 400)
        self.assertEqual(self.post('/users/missing/token').status_code, 404)

    def test_public_status_read_only_and_headers(self):
        token = self.q.create_user('alice', 1024, 3)
        self.q.connect('alice', 's', now=100)
        self.q.account('s', 512, 512, now=101)
        response = self.client.get('/s/' + token)
        self.assertEqual(response.status_code, 200)
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        self.assertEqual(self.client.get('/s/' + 'a'*43).status_code, 404)
        self.assertEqual(self.client.get('/', headers={'Host':'evil.example'}).status_code, 400)
        self.assertEqual(self.post('/users', dict(name='bob', gib='1', days='1')).status_code, 302)
        self.assertEqual(len(self.q.list_users()), 1)

    def test_login_throttle(self):
        for _ in range(10):
            self.assertEqual(self.post('/login', dict(password='wrong')).status_code, 200)
        self.assertEqual(self.login().status_code, 429)

    def test_production_cookie(self):
        self.app.config['SESSION_COOKIE_SECURE'] = True
        response = self.client.get('/login')
        cookie = response.headers['Set-Cookie']
        for flag in ('Secure', 'HttpOnly', 'SameSite=Strict'):
            self.assertIn(flag, cookie)

    def test_configuration_requires_secrets(self):
        with self.assertRaises(RuntimeError):
            create_app({'SECRET_KEY': 'short'})

    def test_profile_download_and_broker_failure(self):
        self.login()
        self.q.create_user('alice', 100, 2)
        self.assertEqual(self.post('/users/alice/profile').status_code, 503)
        self.app.config['VPN_CONFIGURED'] = True
        with patch('app.request_profile', return_value='client\n<key>secret</key>'):
            response = self.post('/users/alice/profile')
            self.assertEqual(response.status_code, 200)
            self.assertIn('attachment', response.headers['Content-Disposition'])
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        with patch('app.request_profile', side_effect=OSError('failed')):
            self.assertEqual(self.post('/users/alice/profile').status_code, 503)
        self.assertEqual(self.post('/users/alice/profile', dict(action='shell')).status_code, 400)

    def test_web_limits_preserve_activation(self):
        self.login()
        self.q.create_user('alice', 100, 2)
        self.q.connect('alice', 'one', now=100)
        self.q.account('one', 10, 20)
        self.assertEqual(self.post('/users/alice/limits', dict(gib='5', days='30')).status_code, 302)
        state = self.q.status('alice')
        self.assertEqual((state.used_bytes, state.first_connected, state.days), (30, 100, 30))
        self.assertEqual(self.post('/users/alice/limits', dict(gib='0', days='30')).status_code, 400)

    def test_search_and_dashboard_totals_not_filtered(self):
        self.login()
        self.q.create_user('alice', 100, 1)
        self.q.create_user('bob', 100, 2)
        self.q.set_enabled('alice', False)
        response = self.client.get('/?q=BOB')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<td>bob', response.data)
        self.assertNotIn(b'<td>alice', response.data)
        for label in (b'Total Users', b'Disabled', b'Expired', b'Online', b'Total traffics',
                      b'CPU USAGE', b'RAM USAGE', b'SWAP USAGE', b'DISK USAGE'):
            self.assertIn(label, response.data)
        response = self.client.get('/?q=%3Cscript%3E')
        self.assertNotIn(b'<script>', response.data)

    def test_backup_settings_masking_download_and_auth(self):
        self.assertEqual(self.client.get('/backups').status_code, 302)
        self.login()
        self.app.config['VPN_CONFIGURED'] = True
        public = dict(enabled=False, interval=15, chat_id='', token_configured=True,
                      encryption_configured=True, state={}, files=[])
        with patch('app.maintenance_request', return_value=public):
            response = self.client.get('/backups')
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'name="token"', response.data)
            self.assertEqual(self.post('/backups/settings', dict(password='wrong',interval='15')).status_code, 403)
            self.assertEqual(self.post('/backups/settings', dict(password='test-password-123',interval='0')).status_code, 400)
            self.assertEqual(self.post('/backups/settings', dict(password='test-password-123',interval='15',passphrase='a'*16,passphrase_repeat='a'*16)).status_code, 302)
            self.assertEqual(self.post('/backups/create').status_code, 302)
        self.app.config['BACKUP_DIRECTORY'] = self.temp.name
        name = 'backup-20261031T000000Z-abcdef12.ovpnbak'
        with open(os.path.join(self.temp.name,name), 'wb') as file: file.write(b'encrypted')
        response = self.client.get('/backups/download/'+name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'encrypted')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        response.close()
        self.assertEqual(self.client.get('/backups/download/panel.env').status_code, 404)
        os.unlink(os.path.join(self.temp.name,name))
        os.symlink(os.path.join(self.temp.name,'test.sqlite'), os.path.join(self.temp.name,name))
        self.assertEqual(self.client.get('/backups/download/'+name).status_code, 404)

    def test_panel_control_requires_password_confirmation_and_csrf(self):
        self.login()
        self.app.config['VPN_CONFIGURED'] = True
        with patch('app.maintenance_request', return_value=dict(scheduled=True)) as broker:
            self.assertEqual(self.post('/system/web', dict(action='stop',password='wrong',confirm='1')).status_code, 403)
            self.assertEqual(self.post('/system/web', dict(action='stop',password='test-password-123')).status_code, 400)
            self.assertEqual(self.post('/system/web', dict(action='reboot',password='test-password-123',confirm='1')).status_code, 400)
            broker.assert_not_called()
            response = self.post('/system/web', dict(action='stop',password='test-password-123',confirm='1'))
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'openvpn-panelctl web-start', response.data)
            broker.assert_called_once_with(dict(operation='web-control',action='stop'))

    def test_network_settings_require_auth_csrf_password_and_confirmation(self):
        self.assertEqual(self.client.get('/settings/network').status_code,302)
        self.login()
        self.app.config['VPN_CONFIGURED']=True
        public=dict(endpoint='192.0.2.1',protocol='udp',port=1194,domain='',caddy_managed=True,
                    caddy_installed=True,tls=dict(valid=False,expires=None,issuer='',http_ok=False),job={})
        with patch('app.maintenance_request',return_value=public) as broker:
            self.assertEqual(self.client.get('/settings/network').status_code,200)
            self.assertEqual(self.post('/settings/ssl',dict(password='wrong',domain='panel.example.com',confirm='1')).status_code,403)
            self.assertEqual(self.post('/settings/ssl',dict(password='test-password-123',domain='bad.com\n{bad}',confirm='1')).status_code,400)
            self.assertEqual(self.post('/settings/vpn',dict(password='test-password-123',protocol='tcp',endpoint='192.0.2.1')).status_code,400)
            self.assertEqual(self.post('/settings/vpn',dict(password='test-password-123',protocol='tcp',endpoint='vpn.example.com',confirm='1')).status_code,200)
            broker.assert_called_with(dict(operation='vpn-save',protocol='tcp',endpoint='vpn.example.com'))
            self.assertEqual(self.post('/settings/ssl',dict(password='test-password-123',domain='panel.example.com',confirm='1',use_for_vpn='1')).status_code,200)
            broker.assert_called_with(dict(operation='ssl-save',domain='panel.example.com',use_for_vpn=True))
