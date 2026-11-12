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

    def test_per_user_simultaneous_connection_create_edit_and_validation(self):
        self.login()
        response=self.post('/users',dict(name='two',gib=50,days=30,max_connections=2))
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.q.status('two').max_connections,2)
        self.assertIn('name="max_connections"',self.client.get('/users/two/edit').text)
        self.assertEqual(self.post('/users/two/limits',dict(gib=50,days=30,max_connections=3)).status_code,302)
        self.assertEqual(self.q.status('two').max_connections,3)
        self.assertEqual(self.post('/users/two/limits',dict(gib=50,days=30)).status_code,302)
        self.assertEqual(self.q.status('two').max_connections,3)
        for value in ('0','101','-1','invalid'):
            self.assertEqual(self.post('/users',dict(name='bad',gib=50,days=30,max_connections=value)).status_code,400)
            self.assertEqual(self.post('/users/two/limits',dict(gib=50,days=30,max_connections=value)).status_code,400)

    def test_static_revalidation_and_dashboard_query_boundary(self):
        asset=self.client.get('/static/style.css')
        self.assertEqual(asset.status_code,200)
        self.assertIn('must-revalidate',asset.headers['Cache-Control'])
        self.assertEqual(self.client.get('/static/style.css',headers={'If-None-Match':asset.headers['ETag']}).status_code,304)
        self.login()
        with patch.object(self.q,'list_users',side_effect=AssertionError('dashboard must not load every user')):
            dashboard=self.client.get('/')
        self.assertEqual(dashboard.status_code,200)
        self.assertEqual(dashboard.headers['Cache-Control'],'no-store')
        self.assertIn(b'data-user-filters',dashboard.data)

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

    def test_subscription_transport_selection_stays_scoped_and_csrf_protected(self):
        self.app.config['VPN_CONFIGURED']=True
        token=self.q.create_user('alice',100,30)
        page=self.client.get('/s/'+token)
        self.assertIn(b'data-device-guide',page.data)
        with self.client.session_transaction() as session: csrf=session['csrf']
        with patch('app.request_profile',return_value='client') as broker:
            response=self.client.post('/s/'+token+'/profile',data=dict(csrf=csrf,transport='tcp'))
            self.assertEqual(response.status_code,200)
            broker.assert_called_once_with('alice','download-tcp')
        with patch('app.request_profile') as broker:
            self.assertEqual(self.client.post('/s/'+token+'/profile',data=dict(csrf=csrf,transport='shell')).status_code,400)
            self.assertEqual(self.client.post('/s/'+token+'/profile',data=dict(transport='udp')).status_code,400)
            broker.assert_not_called()

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
        self.assertIn(b'<bdi class="user-name">bob', response.data)
        self.assertNotIn(b'<bdi class="user-name">alice', response.data)
        for label in (b'Total Users', b'Disabled', b'Expired', b'Online', b'Total traffics',
                      b'CPU USAGE', b'RAM USAGE', b'SWAP USAGE', b'DISK USAGE'):
            self.assertIn(label, response.data)
        response = self.client.get('/?q=%3Cscript%3E')
        self.assertNotIn(b'<script>', response.data)

    def test_restore_upload_requires_auth_csrf_password_confirmation_and_bounds(self):
        import io
        self.assertEqual(self.client.get('/backups/restore/status').status_code,302)
        self.assertEqual(self.client.post('/backups/restore').status_code,302)
        self.login()
        self.app.config['VPN_CONFIGURED']=True
        def send(**changes):
            data=dict(password='test-password-123',confirm='1',backup=(io.BytesIO(b'x'*40000),'../../bad-name.ovpnbak'))
            data.update(changes)
            return self.post('/backups/restore',data)
        with patch('app.upload_restore',return_value={'job_id':'a'*32}) as upload:
            self.assertEqual(send(password='wrong').status_code,403)
            self.assertEqual(send(confirm='0').status_code,400)
            upload.assert_not_called()
            response=send()
            self.assertEqual(response.status_code,200)
            self.assertIn('data-restore-progress',response.text)
            upload.assert_called_once_with(b'x'*40000,'')
            self.assertEqual(send(backup=(io.BytesIO(b''),'empty')).status_code,413)
        with patch('app.upload_restore',side_effect=ValueError('private detail')):
            response=send()
            self.assertEqual(response.status_code,400)
            self.assertNotIn('private detail',response.text)
        with patch('app.upload_restore',side_effect=OSError('disconnected')):
            response=send()
            self.assertEqual(response.status_code,503)
            self.assertNotIn('disconnected',response.text)
        with patch('app.maintenance_request',return_value={'job_id':'a'*32,'status':'completed'}):
            response=self.client.get('/backups/restore/status')
            self.assertEqual(response.json['status'],'completed')
            self.assertEqual(response.headers['Cache-Control'],'no-store')

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

    def test_explicit_telegram_send_and_safe_bilingual_diagnostics(self):
        self.login();self.app.config['VPN_CONFIGURED']=True
        with patch('app.maintenance_request',return_value={}) as broker:
            self.assertEqual(self.post('/backups/create',dict(send_now='1')).status_code,302)
            broker.assert_called_once_with(dict(operation='backup-create',send_now=True))
        public=dict(enabled=False,interval=15,chat_id='123',token_configured=True,telegram_configured=True,
            encryption_configured=False,files=[],restore={},state=dict(last_error='telegram_failed',telegram_error='chat_not_found',telegram_status='failed'))
        with patch('app.maintenance_request',return_value=public):
            response=self.client.get('/backups')
            self.assertIn('name="send_now"',response.text)
            self.assertIn('/start',response.text)
            self.assertIn('chat_not_found',response.text)
            self.client.set_cookie('panel-language','en')
            response=self.client.get('/backups')
            self.assertIn('Chat not found',response.text)
            self.assertIn('Send now works independently',response.text)

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

    def test_subscriber_portal_guides_and_non_rotating_private_download(self):
        token = self.q.create_user('alice', 1024**3, 30)
        self.q.create_user('bob', 1024**3, 30)
        self.app.config['VPN_CONFIGURED'] = True
        public = self.app.test_client()
        page = public.get('/s/' + token)
        for label in ('راهنمای اتصال', 'اندروید', 'آیفون', 'ویندوز', 'حجم کل', 'سپری‌شده'):
            self.assertIn(label.encode(), page.data)
        self.assertIn(b'id="tab-guide"', page.data)
        self.assertIn("script-src 'self'", page.headers['Content-Security-Policy'])
        self.assertIn(b'name="csrf"', page.data)
        with public.session_transaction() as session:
            csrf = session['csrf']
        with patch('app.request_profile', return_value='client\n<key>private</key>') as broker:
            self.assertEqual(public.get('/s/'+token+'/profile').status_code,405)
            self.assertEqual(public.post('/s/'+token+'/profile').status_code,400)
            result=public.post('/s/'+token+'/profile',data=dict(csrf=csrf,name='bob',action='rotate'))
            self.assertEqual(result.status_code,200)
            broker.assert_called_once_with('alice','download')
            self.assertEqual(result.headers['Cache-Control'],'no-store')
            self.assertIn('alice.ovpn',result.headers['Content-Disposition'])
            self.assertIn('noindex',result.headers['X-Robots-Tag'])
        self.assertIsNone(self.q.status('alice').first_connected)
        new_token=self.q.rotate_token('alice')
        self.assertEqual(public.post('/s/'+token+'/profile',data=dict(csrf=csrf)).status_code,404)
        self.q.set_enabled('alice',False)
        with patch('app.request_profile') as broker:
            self.assertEqual(public.post('/s/'+new_token+'/profile',data=dict(csrf=csrf)).status_code,403)
            broker.assert_not_called()

    def test_subscriber_download_exhaustion_expiry_failure_and_throttle(self):
        token=self.q.create_user('alice',1024,1)
        self.app.config['VPN_CONFIGURED']=True
        self.client.get('/s/'+token)
        with self.client.session_transaction() as session:
            csrf=session['csrf']
        with patch('app.request_profile',side_effect=OSError('private-path-never-public')):
            result=self.client.post('/s/'+token+'/profile',data=dict(csrf=csrf))
            self.assertEqual(result.status_code,503)
            self.assertNotIn(b'private-path-never-public',result.data)
        with patch('app.request_profile',return_value='profile') as broker:
            for _ in range(5):
                self.assertEqual(self.client.post('/s/'+token+'/profile',data=dict(csrf=csrf)).status_code,200)
            self.assertEqual(self.client.post('/s/'+token+'/profile',data=dict(csrf=csrf)).status_code,429)
            self.assertEqual(broker.call_count,5)
        self.q.connect('alice','old',now=1)
        self.assertEqual(self.client.post('/s/'+token+'/profile',data=dict(csrf=csrf)).status_code,403)
        self.q.update_limits('alice',1024,3650)
        self.q.account('old',1024,0)
        self.assertEqual(self.client.post('/s/'+token+'/profile',data=dict(csrf=csrf)).status_code,403)


    def test_ssl_bad_confirmation_password_is_explained_before_dns_or_broker(self):
        self.login()
        self.app.config['VPN_CONFIGURED']=True
        with patch('app.maintenance_request') as broker:
            result=self.post('/settings/ssl',dict(password='wrong-root-password',domain='myself-backup.ir',confirm='1',use_for_vpn='1'))
            self.assertEqual(result.status_code,403)
            self.assertIn('رمز فعلی ورود مدیر پنل'.encode(),result.data)
            self.assertIn('درخواست تغییر تنظیمات اجرا نشده است'.encode(),result.data)
            self.assertNotIn(b'wrong-root-password',result.data)
            broker.assert_not_called()

    def test_quick_create_defaults_and_multiple_users_without_navigation(self):
        self.login()
        page=self.client.get('/')
        self.assertIn(b'data-create-user',page.data)
        self.assertIn(b'name="gib" min="1" max="100000" value="50"',page.data)
        self.client.get('/login')
        with self.client.session_transaction() as session:
            csrf=session['csrf']
        for name in ('alice','bob','charlie'):
            response=self.client.post('/users',data=dict(csrf=csrf,name=name),headers={'Accept':'application/json'})
            self.assertEqual(response.status_code,200)
            self.assertTrue(response.is_json)
            self.assertEqual(response.json['name'],name)
            self.assertIn('/s/',response.json['subscription_url'])
            self.assertEqual(response.headers['Cache-Control'],'no-store')
            self.assertEqual(self.q.status(name).limit_bytes,50*1024**3)
            self.assertEqual(self.q.status(name).days,30)
            self.assertIsNone(self.q.status(name).first_connected)
            path=response.json['subscription_url'].split('http://localhost',1)[-1]
            self.assertEqual(self.client.get(path).status_code,200)
        self.assertEqual(len(self.q.list_users()),3)

    def test_quick_create_duplicate_validation_auth_and_csrf(self):
        self.login()
        self.client.get('/login')
        with self.client.session_transaction() as session:
            csrf=session['csrf']
        headers={'Accept':'application/json'}
        self.assertEqual(self.client.post('/users',data=dict(name='alice'),headers=headers).status_code,400)
        first=self.client.post('/users',data=dict(csrf=csrf,name='alice',gib=75,days=60),headers=headers)
        self.assertEqual(first.status_code,200)
        duplicate=self.client.post('/users',data=dict(csrf=csrf,name='alice',gib=50,days=30),headers=headers)
        self.assertEqual(duplicate.status_code,400)
        self.assertIn('قبلاً',duplicate.json['error'])
        self.assertNotIn('subscription_url',duplicate.json)
        self.assertEqual(self.q.status('alice').limit_bytes,75*1024**3)
        self.assertEqual(self.q.status('alice').days,60)
        for name,gib,days in [('<script>',50,30),('bob',0,30),('bob',50,0),('bob','',30)]:
            response=self.client.post('/users',data=dict(csrf=csrf,name=name,gib=gib,days=days),headers=headers)
            self.assertEqual(response.status_code,400)
            self.assertTrue(response.is_json)
        self.post('/logout')
        self.client.get('/login')
        with self.client.session_transaction() as session:
            csrf=session['csrf']
        self.assertEqual(self.client.post('/users',data=dict(csrf=csrf,name='bob'),headers=headers).status_code,302)

    def test_create_without_javascript_keeps_form_and_selected_limits(self):
        self.login()
        response=self.post('/users',dict(name='alice',gib=80,days=90))
        self.assertEqual(response.status_code,200)
        self.assertIn(b'data-create-user',response.data)
        self.assertIn(b'value="80"',response.data)
        self.assertIn(b'value="90"',response.data)
        self.assertIn(b'/s/',response.data)
        invalid=self.post('/users',dict(name='alice',gib=80,days=90))
        self.assertEqual(invalid.status_code,400)
        self.assertIn(b'value="alice"',invalid.data)
        self.assertIn(b'data-create-user',invalid.data)

    def test_user_pagination_sizes_boundaries_and_search(self):
        self.login()
        for i in range(55): self.q.create_user(f'p{i:03}',1024,30)
        response=self.client.get('/')
        self.assertEqual(response.data.count(b'<bdi class="user-name">p'),20)
        self.assertIn('صفحهٔ 1 از 3'.encode(),response.data)
        second=self.client.get('/?page=2&per_page=20')
        self.assertEqual(second.data.count(b'<bdi class="user-name">p'),20)
        self.assertNotIn(b'<bdi class="user-name">p054',second.data)
        self.assertIn(b'<bdi class="user-name">p034',second.data)
        large=self.client.get('/?per_page=50')
        self.assertEqual(large.data.count(b'<bdi class="user-name">p'),50)
        last=self.client.get('/?page=999&per_page=50')
        self.assertEqual(last.data.count(b'<bdi class="user-name">p'),5)
        self.assertIn('صفحهٔ 2 از 2'.encode(),last.data)
        for query in ('page=bad&per_page=bad','page=-3&per_page=100000','page='+('9'*5000)):
            result=self.client.get('/?'+query)
            self.assertEqual(result.status_code,200)
            self.assertEqual(result.data.count(b'<bdi class="user-name">p'),20 if not query.startswith('page=999') else 15)
        all_rows=self.client.get('/?per_page=100')
        self.assertEqual(all_rows.data.count(b'<bdi class="user-name">p'),55)
        filtered=self.client.get('/?q=p05&per_page=50&page=999')
        self.assertEqual(filtered.data.count(b'<bdi class="user-name">p'),5)
        self.assertIn(b'55',filtered.data)
        empty=self.client.get('/?q=missing&page=3')
        self.assertIn('نمایش 0 تا 0 از 0 نتیجه'.encode(),empty.data)

    def test_status_filter_and_pagination_query_state(self):
        self.login()
        for i in range(25):
            self.q.create_user(f'off{i:02}',1024,30)
            self.q.set_enabled(f'off{i:02}',False)
        self.q.create_user('active',1024,30)
        page=self.client.get('/?status=disabled&q=off&per_page=20')
        self.assertEqual(page.data.count(b'<bdi class="user-name">off'),20)
        self.assertIn(b'status=disabled',page.data)
        self.assertIn(b'per_page=20',page.data)
        self.assertIn(b'q=off',page.data)
        self.assertIn(b'page=2',page.data)
        self.assertNotIn(b'<bdi class="user-name">active',page.data)
        active=self.client.get('/?status=active&per_page=50')
        self.assertIn(b'<bdi class="user-name">active',active.data)
        self.assertNotIn(b'<bdi class="user-name">off',active.data)
        with patch('app.online_users',return_value=None):
            online=self.client.get('/?status=online')
            self.assertIn('دادهٔ تازهٔ آنلاین در دسترس نیست'.encode(),online.data)

    def test_user_edit_returns_to_local_paginated_filtered_list(self):
        self.login()
        self.q.create_user('alice',1024,30)
        result=self.post('/users/alice/toggle',dict(enabled='0',q='ali',status='disabled',page='2',per_page='50',next='https://evil.example'))
        self.assertEqual(result.status_code,302)
        self.assertTrue(result.headers['Location'].startswith('/?'))
        self.assertIn('per_page=50',result.headers['Location'])
        self.assertIn('page=2',result.headers['Location'])
        self.assertIn('#users',result.headers['Location'])
        self.assertNotIn('evil.example',result.headers['Location'])

    def test_page_size_preference_and_public_theme_separation(self):
        self.login()
        self.client.get('/?per_page=50')
        page=self.client.get('/')
        self.assertIn(b'value="50" selected',page.data)
        self.assertIn(b'data-theme-toggle',page.data)
        token=self.q.create_user('alice',1024,30)
        public=self.client.get('/s/'+token)
        self.assertIn(b'class="customer"',public.data)
        self.assertNotIn(b'data-theme-toggle',public.data)

    def test_near_limit_near_expiry_and_exhausted_filters(self):
        import time
        self.login()
        now=int(time.time())
        self.q.create_user('near_volume',100,30)
        self.q.connect('near_volume','volume',now=now)
        self.q.account('volume',95,0,now=now)
        self.q.create_user('near_date',100,1)
        self.q.connect('near_date','date',now=now)
        self.q.create_user('exhausted',100,30)
        self.q.connect('exhausted','empty',now=now)
        self.q.account('empty',100,0,now=now)
        self.q.create_user('expired_date',100,1)
        self.q.connect('expired_date','past',now=1)
        for status,name in [('near_limit','near_volume'),('near_expiry','near_date'),('limited','exhausted'),('expired','expired_date')]:
            response=self.client.get('/?status='+status)
            self.assertIn(('<bdi class="user-name">'+name).encode(),response.data)
            self.assertEqual(response.data.count(b'<bdi class="user-name">'),1)

    def test_live_metrics_require_admin_and_do_not_cache(self):
        self.assertEqual(self.client.get('/api/metrics').status_code,302)
        self.login()
        with patch('app.host_metrics',return_value={'cpu':12.5,'ram':30,'swap':0,'disk':15}):
            response=self.client.get('/api/metrics')
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json['cpu'],12.5)
            self.assertEqual(response.headers['Cache-Control'],'no-store')
        with patch('app.host_metrics',return_value={'cpu':None}):
            self.assertIsNone(self.client.get('/api/metrics').json['cpu'])

    def test_direct_row_actions_edit_and_copy_without_rotating(self):
        self.login()
        created=self.post('/users',dict(name='alice',gib=50,days=30))
        import re
        token=re.search(rb'/s/([A-Za-z0-9_-]{43})',created.data).group(1).decode()
        page=self.client.get('/')
        for marker in (b'edit-action',b'copy-action',b'delete-action',b'data-user-dialog'):
            self.assertIn(marker,page.data)
        self.assertNotIn('مدیریت اشتراک ‹'.encode(),page.data)
        self.assertEqual(self.client.get('/users/alice/edit').status_code,200)
        self.client.get('/login')
        with self.client.session_transaction() as session: csrf=session['csrf']
        for _ in range(2):
            copied=self.client.post('/users/alice/link',data=dict(csrf=csrf),headers={'Accept':'application/json'})
            self.assertEqual(copied.status_code,200)
            self.assertTrue(copied.json['subscription_url'].endswith('/s/'+token))
            self.assertEqual(copied.headers['Cache-Control'],'no-store')
        self.assertIsNotNone(self.q.status_by_token(token))
        self.assertEqual(self.client.post('/users/alice/link').status_code,400)

    def test_legacy_copy_requires_explicit_rotation_and_deleted_users_cannot_return(self):
        self.login()
        token=self.q.create_user('legacy',100,30)
        self.client.get('/login')
        with self.client.session_transaction() as session: csrf=session['csrf']
        legacy=self.client.post('/users/legacy/link',data=dict(csrf=csrf),headers={'Accept':'application/json'})
        self.assertEqual(legacy.status_code,409)
        self.assertTrue(legacy.json['needs_rotation'])
        self.assertIsNotNone(self.q.status_by_token(token))
        self.assertEqual(self.client.get('/users/legacy/delete').status_code,200)
        self.assertEqual(self.post('/users/legacy/delete',dict(confirm_name='wrong')).status_code,400)
        self.assertEqual(self.post('/users/legacy/delete',dict(confirm='1',page=2,per_page=50)).status_code,302)
        self.assertEqual(self.client.get('/s/'+token).status_code,404)
        self.assertEqual(self.client.get('/users/legacy/edit').status_code,404)
        self.assertEqual(self.post('/users/legacy/link').status_code,404)
        self.assertEqual(self.post('/users/legacy/toggle',dict(enabled='1')).status_code,404)
        self.assertEqual(self.post('/users',dict(name='legacy',gib=50,days=30)).status_code,200)

    def test_reset_and_renew_route_keeps_link_and_first_activation(self):
        self.login()
        token=self.q.create_user('renewal',100,30)
        self.q.vpn_connect('renewal','peer',now=100)
        self.q.vpn_account('renewal','peer',40,60,now=101)
        self.q.set_enabled('renewal',False)
        self.assertEqual(self.post('/users/renewal/limits',dict(gib=50,days=30,max_connections=2,reset_plan='1')).status_code,302)
        state=self.q.status_by_token(token)
        self.assertTrue(state.allowed)
        self.assertEqual(state.used_bytes,0)
        self.assertEqual(state.limit_bytes,50*1024**3)
        self.assertEqual(state.first_connected,100)
        self.assertEqual(state.expires_at,state.valid_from+30*86400)
        page=self.client.get('/users/renewal/edit')
        self.assertEqual(page.status_code,200)
        self.assertIn(b'name="renew_now"',page.data)
        delete=self.client.get('/users/renewal/delete')
        self.assertNotIn(b'confirm_name',delete.data)

    def test_deleted_user_actions_require_admin_and_csrf(self):
        self.q.create_user('alice',100,30)
        self.client.get('/login')
        with self.client.session_transaction() as session: csrf=session['csrf']
        for route in ('/users/alice/edit','/users/alice/delete'):
            self.assertEqual(self.client.get(route).status_code,302)
        self.assertEqual(self.client.post('/users/alice/delete',data=dict(csrf=csrf,confirm='1',confirm_name='alice')).status_code,302)
        self.login()
        self.assertEqual(self.client.post('/users/alice/delete',data=dict(confirm='1',confirm_name='alice')).status_code,400)
        self.assertTrue(self.q.status('alice').enabled)
