import json
from pathlib import Path
import tempfile
import time
import unittest
from quota import Quotas
from metrics import online_users, summaries, host_metrics


class MetricsTests(unittest.TestCase):
    def test_fresh_online_not_stale_session_rows(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'online.json'
            self.assertIsNone(online_users(path, now=100))
            path.write_text(json.dumps(dict(updated_at=95, users=['alice','alice'])))
            self.assertEqual(online_users(path, now=100), {'alice'})
            self.assertIsNone(online_users(path, now=111))
            path.write_text('not json')
            self.assertIsNone(online_users(path))

    def test_summary_overlap_and_traffic(self):
        with tempfile.TemporaryDirectory() as temp:
            q = Quotas(str(Path(temp)/'db.sqlite'))
            q.create_user('alice', 100, 1)
            q.create_user('bob', 200, 2)
            q.connect('alice', 'session', now=1)
            q.account('session', 50, 50)
            q.set_enabled('alice', False)
            result = summaries(q.list_users(), {'bob','unknown'})
            self.assertEqual(result, dict(total=2, disabled=1, expired=1, exhausted=1, online=1, traffic=100))
            self.assertIsNone(summaries(q.list_users(), None)['online'])

    def test_real_host_metrics_sane(self):
        for name in ('cpu','ram','swap','disk'):
            self.assertTrue(0 <= host_metrics()[name] <= 100)
