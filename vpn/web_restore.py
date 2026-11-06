"""Bounded broker upload -> private root-owned job -> independent restore worker."""
import fcntl
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from vpn import backups
from vpn.maintenance import ROOT, atomic_json, read_json


def status():
    return read_json(ROOT/'restore-state.json', {})


def queue_upload(message, stream):
    if set(message) != {'operation','size','passphrase'} or message['operation'] != 'backup-restore-upload':
        raise ValueError('Invalid upload fields')
    size, phrase = message['size'], message['passphrase']
    if type(size) is not int or not 0 < size <= backups.MAX_ARCHIVE:
        raise ValueError('Invalid backup size')
    if type(phrase) is not str or len(phrase) > 1024:
        raise ValueError('Invalid legacy password')
    with (ROOT/'restore-upload.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = status()
        if current.get('status') in ('queued','running') and time.time()-current.get('updated_at',0) < 1800:
            raise ValueError('Restore already running')
        jobs = ROOT/'restore-jobs'
        jobs.mkdir(mode=0o700, exist_ok=True)
        # Expired jobs cannot still have a worker: RuntimeMaxSec is 600.
        for old in jobs.iterdir():
            if old.is_dir() and not old.is_symlink() and re.fullmatch('[a-f0-9]{32}',old.name):
                shutil.rmtree(old)
        job_id = uuid.uuid4().hex
        job = jobs/job_id
        job.mkdir(mode=0o700)
        try:
            target = job/'archive'
            with target.open('xb') as out:
                os.chmod(target,0o600)
                remaining = size
                while remaining:
                    chunk = stream.read(min(65536,remaining))
                    if not chunk: raise ValueError('Truncated upload')
                    out.write(chunk)
                    remaining -= len(chunk)
                out.flush()
                os.fsync(out.fileno())
            data = target.read_bytes()
            if data.startswith(backups.MAGIC):
                # Legacy encrypted files remain importable; new files need no password.
                data = backups.decrypt(data,phrase)
            with tempfile.TemporaryDirectory(dir=job) as temp:
                backups.validate_archive(data,Path(temp))  # Reject before downtime.
            # Store only the decoded archive; never persist/log the supplied password.
            target.write_bytes(data)
            target.chmod(0o600)
            state = dict(job_id=job_id,status='queued',updated_at=int(time.time()))
            atomic_json(ROOT/'restore-state.json',state)
            subprocess.run(['/usr/bin/systemd-run','--quiet','--collect',
                '--unit=openvpn-panel-restore-'+job_id,'--on-active=3s',
                '--timer-property=AccuracySec=1s','--property=RuntimeMaxSec=600',
                '/usr/local/sbin/openvpn-panelctl','apply-restore',job_id],
                check=True,capture_output=True,timeout=15)
            return state
        except Exception:
            shutil.rmtree(job,ignore_errors=True)
            if status().get('job_id') == job_id:
                atomic_json(ROOT/'restore-state.json',dict(job_id=job_id,status='failed',updated_at=int(time.time())))
            raise


def apply_job(job_id, restore):
    if type(job_id) is not str or not re.fullmatch('[a-f0-9]{32}',job_id):
        raise ValueError('Invalid restore job')
    with (ROOT/'restore-upload.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        state=status()
        if state.get('job_id') != job_id or state.get('status') != 'queued':
            raise ValueError('No queued restore')
        job=ROOT/'restore-jobs'/job_id
        state.update(status='running',updated_at=int(time.time()))
        atomic_json(ROOT/'restore-state.json',state)
        try:
            restore(str(job/'archive'),yes=True)
        except Exception:
            state.update(status='failed',updated_at=int(time.time()))
            raise
        else:
            state.update(status='completed',updated_at=int(time.time()))
        finally:
            atomic_json(ROOT/'restore-state.json',state)
            shutil.rmtree(job,ignore_errors=True)
