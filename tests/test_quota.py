import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from quota import Quotas

class QuotaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.q = Quotas(os.path.join(self.temp.name, 'quota.sqlite'))
        self.token = self.q.create_user('alice', 100, 2)

    def tearDown(self): self.temp.cleanup()

    def test_connection_limit_atomic_admission_release_and_shared_quota(self):
        self.q.update_limits('alice',10000,30,max_connections=2)
        def attempt(i):
            try:
                self.q.vpn_connect('alice',f'192.0.2.1:{10000+i}',now=100)
                return i
            except PermissionError: return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            admitted=[i for i in pool.map(attempt,range(20)) if i is not None]
        self.assertEqual(len(admitted),2)
        a,b=admitted
        self.q.vpn_account('alice',f'192.0.2.1:{10000+a}',10,20,final=True,now=101)
        self.q.vpn_account('alice',f'192.0.2.1:{10000+b}',30,40,now=101)
        self.q.vpn_connect('alice','192.0.2.2:20000',now=102)
        self.assertEqual(self.q.status('alice',102).used_bytes,100)
        self.assertEqual(self.q.status('alice',102).first_connected,100)
        self.q.update_limits('alice',10000,30,max_connections=1)
        with self.assertRaises(PermissionError): self.q.vpn_connect('alice','192.0.2.3:30000',now=103)
        with self.q._db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM sessions WHERE closed=0').fetchone()[0],2)

    def test_connection_limit_defaults_validation_and_preserved_edit(self):
        self.assertEqual(self.q.status('alice').max_connections,1)
        self.q.create_user('bob',100,2,max_connections=2)
        self.q.update_limits('bob',200,3)
        self.assertEqual(self.q.status('bob').max_connections,2)
        for value in (0,-1,101,True,'2'):
            with self.assertRaises(ValueError): self.q.create_user('bad',100,2,max_connections=value)
            with self.assertRaises(ValueError): self.q.update_limits('bob',100,2,max_connections=value)
        self.q.vpn_connect('bob','192.0.2.1:1')
        with self.assertRaises(PermissionError): self.q.vpn_connect('bob','192.0.2.1:1')

    def test_first_connection_and_expiry(self):
        self.assertIsNone(self.q.status('alice', 50).expires_at)
        self.q.connect('alice', 'session1', 100)
        self.assertEqual(self.q.status('alice', 101).remaining_seconds, 2*86400-1)
        self.assertEqual(self.q.status('alice', 100+2*86400).reason, 'expired')
        with self.assertRaises(PermissionError): self.q.connect('alice', 'session2', 100+2*86400)

    def test_accounting_idempotency_and_limit(self):
        self.q.connect('alice', 's', 10)
        self.q.account('s', 20, 30, now=11)
        self.assertEqual(self.q.account('s', 20, 30, now=11).used_bytes, 50)
        self.assertEqual(self.q.account('s', 40, 60, final=True, now=11).reason, 'volume_exhausted')
        self.assertEqual(self.q.account('s', 40, 60, final=True, now=11).used_bytes, 100)
        with self.assertRaises(ValueError): self.q.account('s', 41, 60)
        with self.assertRaises(PermissionError): self.q.connect('alice', 's2', 12)

    def test_token_and_disable(self):
        self.assertEqual(self.q.status_by_token(self.token).name, 'alice')
        self.assertIsNone(self.q.status_by_token('wrong'))
        self.q.set_enabled('alice', False)
        with self.assertRaises(PermissionError): self.q.connect('alice', 's')

    def test_concurrent_sessions(self):
        for i in range(10): self.q.connect('alice', str(i), 1)
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(lambda i: self.q.account(str(i), 3, 4, now=2), range(10)))
        self.assertEqual(self.q.status('alice', 2).used_bytes, 70)

    def test_out_of_order_rejected(self):
        self.q.connect('alice', 's', 1)
        self.q.account('s', 5, 5, now=2)
        with self.assertRaises(ValueError): self.q.account('s', 4, 5, now=3)
        self.assertEqual(self.q.status('alice', 3).used_bytes, 10)



    def test_remembered_token_encrypted_and_rotation_consistent(self):
        from pathlib import Path
        import sqlite3
        from quota import link_key_path, TokenStorageError
        token=self.q.create_user('remembered',100,30,remember=True)
        self.assertEqual(self.q.remembered_token('remembered'),token)
        with sqlite3.connect(self.q.path) as db:
            cipher=db.execute("SELECT encrypted_token FROM users WHERE name='remembered'").fetchone()[0]
        self.assertNotIn(token,cipher)
        self.assertEqual(link_key_path(self.q.path).stat().st_mode & 0o077,0)
        new=self.q.rotate_token('remembered',remember=True)
        self.assertNotEqual(new,token)
        self.assertIsNone(self.q.status_by_token(token))
        self.assertEqual(self.q.remembered_token('remembered'),new)
        self.assertIsNone(self.q.remembered_token('alice'))
        link_key_path(self.q.path).unlink()
        with self.assertRaises(TokenStorageError): self.q.remembered_token('remembered')
        with self.assertRaises(TokenStorageError): self.q.create_user('cannot_replace_key',100,30,remember=True)
        self.assertFalse(link_key_path(self.q.path).exists())

    def test_delete_tombstone_invalidates_links_and_reserves_certificate_name(self):
        import sqlite3
        self.q.vpn_connect('alice','192.0.2.1:123',now=100)
        self.q.vpn_account('alice','192.0.2.1:123',2,3,now=101)
        self.q.delete_user('alice')
        self.assertEqual(self.q.list_users(),[])
        self.assertIsNone(self.q.status_by_token(self.token))
        self.assertEqual(self.q.total_traffic(),5)
        for action in (lambda:self.q.status('alice'),lambda:self.q.set_enabled('alice',True),lambda:self.q.rotate_token('alice'),lambda:self.q.update_limits('alice',200,30)):
            with self.assertRaises(KeyError): action()
        with self.assertRaises(PermissionError): self.q.vpn_connect('alice','other',now=102)
        with self.assertRaises(sqlite3.IntegrityError): self.q.create_user('alice',100,30)
        self.assertFalse(self.q.vpn_account('alice','192.0.2.1:123',4,5,final=True,now=102).allowed)
        self.assertEqual(self.q.total_traffic(),9)

if __name__ == "__main__": unittest.main()
