"""Speed optimizations must preserve admission and atomic accounting safety."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from quota import Quotas
from vpn.performance import tune_server, BEGIN, END


class TransportTests(unittest.TestCase):
    def test_udp_tcp_and_idempotence(self):
        for protocol,option in [('udp4','fast-io'),('tcp4-server','tcp-nodelay')]:
            source=f'proto {protocol}\nallow-compression no\ndata-ciphers AES-256-GCM:AES-128-GCM\n'
            tuned=tune_server(source)
            self.assertEqual(tune_server(tuned),tuned)
            self.assertIn(source,tuned)
            self.assertIn('\n'+option+'\n',tuned)
            switched=tune_server(tuned.replace('proto '+protocol,'proto '+('tcp4-server' if protocol=='udp4' else 'udp4')))
            self.assertNotIn('\n'+option+'\n',switched)
            self.assertEqual(switched.count(BEGIN),1)
        for invalid in ['proto invalid\n','proto udp4\nproto tcp4-server\n','proto udp4\n'+BEGIN]:
            with self.assertRaises(ValueError): tune_server(invalid)


class AccountingSpeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/'quota.sqlite')
        self.q=Quotas(self.path)
        self.q.create_user('alice',100,30,max_connections=2)
        self.q.vpn_connect('alice','a',now=100)
        self.q.vpn_connect('alice','b',now=100)

    def test_runtime_skips_schema_writes_and_cannot_create_missing_database(self):
        with patch('quota.sqlite3.connect',side_effect=AssertionError('runtime constructor must not perform migrations')):
            existing=Quotas(self.path,initialize=False)
        self.assertEqual(existing.status('alice',now=101).used_bytes,0)
        self.assertEqual(existing.status('alice',now=101).last_auth_code,'accepted')
        missing=Path(self.tmp.name)/'missing'
        with self.assertRaises(sqlite3.OperationalError): Quotas(str(missing),initialize=False).status('alice')
        self.assertFalse(missing.exists())

    def test_batch_one_transaction_shared_quota_and_late_disconnect(self):
        statements=[]
        original=self.q._db
        @contextmanager
        def traced():
            with original() as db:
                db.set_trace_callback(statements.append)
                yield db
        with patch.object(self.q,'_db',traced):
            states=self.q.vpn_account_many([('alice','a',30,30),('alice','b',30,30),('unknown','x',0,0)],now=101)
        self.assertEqual(sum(s=='BEGIN IMMEDIATE' for s in statements),1)
        self.assertEqual(sum(s=='COMMIT' for s in statements),1)
        self.assertEqual([s.reason if s else None for s in states],['volume_exhausted','volume_exhausted',None])
        self.assertEqual(self.q.status('alice',now=101).used_bytes,120)
        self.q.vpn_account('alice','a',30,30,final=True,now=102)
        self.q.update_limits('alice',100,30,reset_usage=True,renew_now=True,now=103)
        result=self.q.vpn_account_many([('alice','a',100,100),('alice','b',35,35)],now=104)
        self.assertEqual(result[0].reason,'session_closed')
        self.assertTrue(result[1].allowed)
        self.assertEqual(self.q.status('alice',now=104).used_bytes,10)

    def test_invalid_snapshot_and_unexpected_error_rollback(self):
        with self.assertRaises(ValueError): self.q.vpn_account_many([('alice','a',10,10),('alice','b',-1,1)])
        self.assertEqual(self.q.status('alice',now=101).used_bytes,0)
        original=self.q._vpn_account
        def failing(db,name,address,*args):
            if address=='b': raise RuntimeError('simulated storage failure')
            return original(db,name,address,*args)
        with patch.object(self.q,'_vpn_account',side_effect=failing):
            with self.assertRaises(RuntimeError): self.q.vpn_account_many([('alice','a',10,10),('alice','b',10,10)])
        self.assertEqual(self.q.status('alice',now=101).used_bytes,0)

    def test_hook_import_does_not_load_subscription_crypto(self):
        subprocess.run([sys.executable,'-c',"import quota,sys; assert 'cryptography.fernet' not in sys.modules"],check=True)
