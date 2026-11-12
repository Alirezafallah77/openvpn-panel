#!/usr/bin/env python3
"""Synthetic control-path benchmark; never accesses a real VPN or production DB.

Run with the project's venv. Measures cold quota setup and accounting for 100
synthetic transports. This is NOT a tunnel throughput or internet speed test.
"""
import json
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from quota import Quotas


def median_ms(operation,runs=7):
    values=[]
    for _ in range(runs):
        start=time.perf_counter()
        operation()
        values.append((time.perf_counter()-start)*1000)
    return round(statistics.median(values),2)


def main():
    with tempfile.TemporaryDirectory() as temp:
        path=str(Path(temp)/'synthetic.sqlite')
        q=Quotas(path)
        q.create_user('synthetic',1024**4,30,max_connections=100)
        for i in range(100): q.vpn_connect('synthetic',str(i),now=100)
        sample=0
        def entries():
            nonlocal sample
            sample+=1000
            return [('synthetic',str(i),sample,sample) for i in range(100)]
        def sequential():
            for row in entries(): q.vpn_account(*row,now=101)
        def batched(): q.vpn_account_many(entries(),now=101)
        def cold(previous):
            # Previous hot path imported subscription encryption and ran schema
            # setup on every invocation; runtime hooks now need neither.
            code=("from cryptography.fernet import Fernet; " if previous else '')
            code+="from quota import Quotas; import sys; Quotas(sys.argv[1],initialize="+str(previous)+").status('synthetic',now=101)"
            subprocess.run([sys.executable,'-c',code,path],cwd=Path(__file__).resolve().parents[1],check=True,stdout=subprocess.DEVNULL)
        print(json.dumps({'transports':100,
            'accounting_sequential_ms':median_ms(sequential),
            'accounting_batch_ms':median_ms(batched),
            'cold_quota_previous_ms':median_ms(lambda:cold(True)),
            'cold_quota_runtime_ms':median_ms(lambda:cold(False))},indent=2))


if __name__=='__main__': main()
