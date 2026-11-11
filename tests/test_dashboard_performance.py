"""SQL pagination must preserve the established dashboard filter semantics."""
import tempfile
import unittest
from unittest.mock import patch
from quota import Quotas

class DashboardQueryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.q=Quotas(self.tmp.name+'/db')
        with self.q._db() as db:
            for i in range(137):
                db.execute('INSERT INTO users(name,token_hash,limit_bytes,days,first_connected,used_bytes,enabled,deleted,valid_from,prior_usage) VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (f'user_{i}',f'token-{i}',100,30,None if i%3==0 else 100,i%101,int(i%5!=0),int(i%11==0),200 if i%7==0 else None,10))
        self.now=100+29*86400

    def test_filters_search_order_pages_and_global_stats_match_legacy(self):
        q=self.q
        online={'user_1','user_12','deleted_name'}
        all_users=q.list_users(now=self.now)
        checks={
            'all':lambda u:True, 'active':lambda u:u.allowed,
            'disabled':lambda u:not u.enabled,
            'expired':lambda u:u.remaining_seconds is not None and u.remaining_seconds<=0,
            'limited':lambda u:u.remaining_bytes==0,
            'online':lambda u:u.name in online,
            'near_limit':lambda u:u.allowed and u.remaining_bytes<=u.limit_bytes*.1,
            'near_expiry':lambda u:u.allowed and u.remaining_seconds is not None and u.remaining_seconds<=3*86400,
        }
        for now in (self.now,self.now+3*86400):
            all_users=q.list_users(now=now)
            for status,check in checks.items():
                for search in ('','USER_1','%','_12','ß'*64):
                    expected=[u for u in all_users if search.casefold() in u.name.casefold() and check(u)]
                    for page in (1,2,999):
                        with self.subTest(now=now,status=status,search=search,page=page):
                            result=q.dashboard_page(search,status,page,20,online,now)
                            actual_page=min(page,max(1,(len(expected)+19)//20))
                            self.assertEqual(result['total'],len(expected))
                            self.assertEqual(result['page'],actual_page)
                            self.assertEqual(result['users'],expected[(actual_page-1)*20:actual_page*20])
                            self.assertEqual(result['stats']['total'],len(all_users))
                            self.assertEqual(result['stats']['online'],len({u.name for u in all_users}&online))
                            self.assertEqual(result['stats']['traffic'],q.total_traffic())
                            self.assertEqual(result['stats']['expired'],sum(u.expires_at is not None and u.expires_at<=now for u in all_users))

    def test_only_page_rows_are_materialized_and_unknown_online_is_preserved(self):
        with patch.object(self.q,'_status',wraps=self.q._status) as status:
            result=self.q.dashboard_page(per_page=20,now=self.now)
            self.assertEqual(status.call_count,20)
            self.assertIsNone(result['stats']['online'])
        empty=self.q.dashboard_page(status='online',online=None,now=self.now)
        self.assertEqual(empty['users'],[])
        self.assertEqual(empty['pages'],1)
        with self.assertRaises(ValueError): self.q.dashboard_page(status='unknown')
