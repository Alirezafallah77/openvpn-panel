import os
import tempfile
import unittest
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
