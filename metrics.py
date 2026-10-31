"""Read-only host metrics and fresh collector observations (not stale sessions)."""
import json
from pathlib import Path
import time
import psutil


def host_metrics():
    memory, swap = psutil.virtual_memory(), psutil.swap_memory()
    disk = psutil.disk_usage('/')
    return dict(cpu=psutil.cpu_percent(interval=0.1), ram=memory.percent,
                ram_used=memory.total-memory.available, ram_total=memory.total,
                swap=swap.percent, swap_used=swap.used, swap_total=swap.total,
                disk=disk.percent, disk_used=disk.used, disk_total=disk.total)


def online_users(path, now=None):
    now = time.time() if now is None else now
    try:
        data = json.loads(Path(path).read_text())
        if not 0 <= now - data['updated_at'] <= 15 or not isinstance(data['users'], list):
            return None
        if not all(isinstance(name, str) for name in data['users']):
            return None
        return set(data['users'])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def summaries(users, online):
    # Expired and disabled are independent and may overlap.
    now = int(time.time())
    return dict(total=len(users), disabled=sum(not u.enabled for u in users),
                expired=sum(u.expires_at is not None and now >= u.expires_at for u in users),
                exhausted=sum(u.used_bytes >= u.limit_bytes for u in users),
                online=None if online is None else len({u.name for u in users} & online),
                traffic=sum(u.used_bytes for u in users))
