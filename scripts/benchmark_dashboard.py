#!/usr/bin/env python3
"""Synthetic dashboard-query benchmark; never opens a production database.

Run: .venv/bin/python scripts/benchmark_dashboard.py --users 10000
Reports median wall time and separately traced peak Python allocations. SQLite's
native memory and template/CPU sampling time are deliberately not included.
"""
import argparse
import gc
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
import tracemalloc

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from quota import Quotas
from metrics import summaries


def measure(operation):
    timings=[]
    for _ in range(5):
        started=time.perf_counter()
        operation()
        timings.append((time.perf_counter()-started)*1000)
    gc.collect()
    tracemalloc.start()
    operation()
    _,peak=tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {'median_ms':round(statistics.median(timings),2),'peak_python_kib':round(peak/1024,1)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--users',type=int,default=10000)
    args=parser.parse_args()
    if not 1<=args.users<=100000: parser.error('users must be between 1 and 100000')
    with tempfile.TemporaryDirectory() as directory:
        q=Quotas(str(Path(directory)/'synthetic.sqlite'))
        with q._db() as db:
            db.execute('BEGIN')
            db.executemany('INSERT INTO users(name,token_hash,limit_bytes,days,used_bytes,first_connected) VALUES(?,?,?,?,?,?)',
                ((f'user_{i:06}',f'token-{i}',50*1024**3,30,i*1000,100) for i in range(args.users)))
        now=200
        online={f'user_{i:06}' for i in range(0,args.users,5)}
        def previous():
            users=q.list_users(now=now)
            stats=summaries(users,online)
            stats['traffic']=q.total_traffic()
            filtered=[u for u in users if '' in u.name.casefold()]
            return filtered[:20],len(filtered),stats
        def current(): return q.dashboard_page(online=online,now=now)
        old=previous();new=current()
        assert old[0]==new['users'] and old[1]==new['total']
        print(json.dumps({'users':args.users,'page_size':20,'previous':measure(previous),'current':measure(current)},indent=2))


if __name__=='__main__': main()
