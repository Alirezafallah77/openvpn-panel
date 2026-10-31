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

if __name__ == '__main__': unittest.main()
