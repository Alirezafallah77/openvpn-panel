from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from flask import g
from app import create_app
from i18n import format_date, parse_date, translate
from panel_web import admin_path, public_port


class PanelPreferencesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.password = generate_password_hash('testing-password')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app(dict(TESTING=True, SECRET_KEY='s'*40, ADMIN_PASSWORD_HASH=self.password,
            DATABASE=str(Path(self.temp.name)/'db.sqlite'), ADMIN_PATH='/secret-panel',
            SESSION_COOKIE_SECURE=False, VPN_CONFIGURED=True))
        self.client = self.app.test_client()
        self.q = self.app.extensions['quotas']

    def tearDown(self): self.temp.cleanup()

    def csrf(self):
        self.client.get('/secret-panel/login')
        with self.client.session_transaction() as s: return s['csrf']

    def login(self):
        return self.client.post('/secret-panel/login',data={'csrf':self.csrf(),'password':'testing-password'})

    def test_mount_hides_old_routes_and_builds_public_links_without_prefix(self):
        for path in ('/', '/login', '/settings/network', '/users', '/api/metrics', '/secret-panel-other/login'):
            self.assertEqual(self.client.get(path).status_code,404,path)
        self.assertEqual(self.client.post('/users').status_code,404)
        self.assertEqual(self.client.get('/secret-panel/').location,'/secret-panel/login')
        self.assertEqual(self.login().location,'/secret-panel/')
        token=self.q.create_user('test',1024,30)
        r=self.client.get('/s/'+token)
        self.assertEqual(r.status_code,200)
        self.assertIn(f'action="/s/{token}/profile"',r.text)
        r=self.client.get('/secret-panel/')
        self.assertIn('href="/static/style.css"',r.text)
        self.assertIn('action="/secret-panel/users"',r.text)
        with self.client.get('/static/style.css') as response:
            self.assertEqual(response.status_code,200)

    def test_preferences_csrf_validation_redirect_and_browser_isolation(self):
        self.assertEqual(self.client.post('/preferences',data={'language':'en'}).status_code,400)
        csrf=self.csrf()
        self.assertIn('name="next" value="/secret-panel/login"', self.client.get('/secret-panel/login').text)
        for target in ('https://evil.test','//evil.test','/\\evil.test','/\n/evil.test'):
            self.assertEqual(self.client.post('/preferences',data={'csrf':csrf,'language':'en','next':target}).status_code,400)
        self.assertEqual(self.client.post('/preferences',data={'csrf':csrf,'language':'de'}).status_code,400)
        r=self.client.post('/preferences',data={'csrf':csrf,'language':'en','calendar':'jalali','next':'/secret-panel/login'})
        self.assertEqual(r.location,'/secret-panel/login')
        self.assertIn('HttpOnly',r.headers.getlist('Set-Cookie')[0])
        r=self.client.get('/secret-panel/login')
        self.assertIn('<html lang="en" dir="ltr">',r.text)
        self.assertIn('Sign in to dashboard',r.text)
        self.assertIn('lang="fa" dir="rtl"',self.app.test_client().get('/secret-panel/login').text)
        self.client.set_cookie('panel-language','invalid')
        self.client.set_cookie('panel-calendar','invalid')
        self.assertIn('lang="fa"',self.client.get('/secret-panel/login').text)

    def test_all_english_templates_compile_and_translate_messages(self):
        self.client.set_cookie('panel-language','en')
        self.login()
        settings=dict(endpoint='vpn.example.com',protocol='udp',port=1194,domain='panel.example.com',public_port=443,
            admin_path='/secret-panel',caddy_managed=True,caddy_installed=True,tls=dict(valid=False,expires=None,issuer='',http_ok=False),job={})
        with self.app.test_request_context('/'):
            g.language='en';g.calendar='jalali'
            for name in Path('templates').glob('*.html'): self.app.jinja_env.get_template(name.name)
        with patch('app.maintenance_request',return_value=settings):
            r=self.client.get('/secret-panel/settings/network')
        self.assertEqual(r.status_code,200)
        self.assertIn('Panel address and port',r.text)
        self.assertIn('Network settings',r.text)
        self.assertIn('Current public port',r.text)
        # Source translation must not translate dynamic strings/unsafe content.
        with self.app.test_request_context('/'):
            g.language='en'
            self.assertEqual(translate('رمز عبور نادرست است.'),'Incorrect password.')
        bad=self.client.post('/secret-panel/settings/panel',data={'csrf':self.csrf(),'password':'wrong'})
        self.assertEqual(bad.status_code,403)
        self.assertIn('Incorrect confirmation password',bad.text)

    def test_panel_request_requires_auth_confirmation_and_strict_values(self):
        self.assertEqual(self.client.post('/secret-panel/settings/panel',data={'csrf':self.csrf()}).location,'/secret-panel/login')
        self.login()
        data=dict(csrf=self.csrf(),password='testing-password',confirm='1',public_port='5000',custom_path='1',admin_path='/admin-two')
        with patch('app.maintenance_request',return_value={'queued':True}) as broker:
            r=self.client.post('/secret-panel/settings/panel',data=data)
            self.assertEqual(r.status_code,200)
            self.assertIn('/admin-two/login',r.text)
            broker.assert_called_once_with(dict(operation='panel-save',public_port=5000,admin_path='/admin-two'))
        for changes in ({'confirm':'0'},{'public_port':'8000'},{'public_port':'443\n'},{'admin_path':'/s'},{'admin_path':'/x/y'}):
            self.assertEqual(self.client.post('/secret-panel/settings/panel',data=data|changes).status_code,400)

    def test_ssl_pending_address_keeps_current_port_and_admin_path(self):
        self.login()
        with patch('app.maintenance_request',return_value={'queued':True,'public_port':5000}):
            response=self.client.post('/secret-panel/settings/ssl',data=dict(csrf=self.csrf(),password='testing-password',confirm='1',domain='new.example.com'))
        self.assertEqual(response.status_code,200)
        self.assertIn('https://new.example.com:5000/secret-panel',response.text)

    def test_calendar_known_boundaries_and_unchanged_storage(self):
        self.assertEqual(parse_date('1403-01-01','jalali').isoformat(),'2024-03-20')
        self.assertEqual(parse_date('۱۴۰۳-۱۲-۳۰','jalali').isoformat(),'2025-03-20')
        for value in ('1402-12-30','1403-07-31','1403-00-01','1403-1-01'):
            with self.assertRaises(ValueError): parse_date(value,'jalali')
        ts=int(datetime(2024,3,20,10,20,30,tzinfo=timezone.utc).timestamp())
        self.assertEqual(format_date(ts,'jalali'),'1403-01-01 10:20:30 UTC (Jalali)')
        self.assertEqual(format_date(ts,'gregorian'),'2024-03-20 10:20:30 UTC')
        self.q.create_user('dateuser',1024**3,30)
        self.q.connect('dateuser','session',now=ts)
        self.login();self.client.set_cookie('panel-calendar','jalali')
        r=self.client.get('/secret-panel/users/dateuser/edit')
        self.assertEqual(r.status_code,200)
        self.assertIn('1403-01-31',r.text)
        r=self.client.post('/secret-panel/users/dateuser/limits',data=dict(csrf=self.csrf(),gib=2,days=30,set_expiry_date='1',expiry_date='1403-02-01'))
        self.assertEqual(r.status_code,302)
        state=self.q.status('dateuser')
        self.assertEqual(state.days,31)
        self.assertEqual(state.first_connected,ts)
        self.assertEqual(state.used_bytes,0)
        self.assertEqual(state.expires_at,ts+31*86400)
        self.assertEqual(self.client.post('/secret-panel/users/dateuser/limits',data=dict(csrf=self.csrf(),gib=2,days=30,set_expiry_date='1',expiry_date='1402-12-30')).status_code,400)

    def test_strict_validators(self):
        for value in (0,80,444,1023,8000,2019,True,None,'۴۴۳','443\n',65536):
            with self.assertRaises(ValueError): public_port(value)
        for value in (443,5000,'65535'): self.assertEqual(public_port(value),int(value))
        for value in ('/s','/static','/preferences','/a/b','/x?y','/x\n','/سلام',None):
            with self.assertRaises(ValueError): admin_path(value)
        self.assertEqual(admin_path('/my-admin'),'/my-admin')
