"""Renewal, serial admission and authoritative-session reconciliation regressions."""
import tempfile
import unittest
from quota import Quotas, normalize_serial

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.q=Quotas(self.tmp.name+'/quota.db')
        self.token=self.q.create_user('alice',100,30)

    def test_renew_preserves_link_activation_and_live_counter_baselines(self):
        q=self.q
        self.assertIsNone(q.status('alice',now=90).expires_at)
        q.vpn_connect('alice','peer',now=100)
        q.vpn_account('alice','peer',20,30,now=101)
        q.set_enabled('alice',False)
        q.update_limits('alice',100,30,reset_usage=True,renew_now=True,enable=True,now=100000)
        state=q.status_by_token(self.token,now=100000)
        self.assertTrue(state.allowed)
        self.assertEqual(state.used_bytes,0)
        self.assertEqual(state.first_connected,100)
        self.assertEqual(state.expires_at,100000+30*86400)
        self.assertEqual(q.total_traffic(),50)
        self.assertEqual(q.vpn_account('alice','peer',22,33,now=100001).used_bytes,5)
        self.assertEqual(q.total_traffic(),55)
        q.update_limits('alice',200,31,now=100002)
        self.assertEqual(q.status('alice',now=100003).expires_at,100000+31*86400)
        self.assertEqual(q.status('alice',now=100003).used_bytes,5)

    def test_new_unactivated_user_explicit_renewal_starts_now(self):
        self.q.update_limits('alice',100,30,renew_now=True,now=100)
        self.assertIsNone(self.q.status('alice',now=101).first_connected)
        self.assertEqual(self.q.status('alice',now=101).expires_at,100+30*86400)

    def test_reconcile_has_admission_grace_and_keeps_live_slots(self):
        q=self.q
        q.vpn_connect('alice','peer',now=100)
        q.reconcile_sessions([],now=129)
        with self.assertRaisesRegex(PermissionError,'connection_limit'): q.vpn_connect('alice','other',now=129)
        q.reconcile_sessions([('alice','peer')],now=200)
        self.assertTrue(q.session_registered('alice','peer'))
        q.reconcile_sessions([],now=201)
        self.assertFalse(q.session_registered('alice','peer'))
        self.assertFalse(q.vpn_account('alice','peer',20,30,now=202).allowed)
        q.vpn_connect('alice','other',now=202)

    def test_certificate_serial_and_safe_diagnostics(self):
        self.assertEqual(normalize_serial('00:0a:BC'),'ABC')
        with self.q._db() as db: db.execute("UPDATE users SET cert_serial='ABC'")
        for serial in (None,'123','garbage',':\n'):
            with self.assertRaisesRegex(PermissionError,'old_certificate'): self.q.vpn_connect('alice','peer',serial=serial,now=100)
        self.q.vpn_connect('alice','peer',serial='00:0a:BC',now=100)
        self.q.record_auth('alice','accepted',now=100)
        self.assertEqual(self.q.status('alice',now=100).last_auth_code,'accepted')
        with self.assertRaises(ValueError): self.q.record_auth('alice','raw-secret')
