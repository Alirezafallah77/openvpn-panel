"""Destructive end-to-end test. ONLY on an ephemeral Ubuntu 24.04 runner as root.

Invoked after install.sh; exercises actual OpenVPN, systemd, hooks, certificates,
web downloads, accounting, disconnect, reconnect rejection and fail-closed.
"""
import http.cookiejar
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, '/opt/openvpn-panel')
from quota import Quotas

BASE = os.environ.get('PANEL_TEST_BASE', 'http://localhost:8000')
PASSWORD = 'integration-only-password-123'


def cmd(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def wait_for(predicate, description, timeout=40):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            print('PASS:', description, flush=True)
            return
        time.sleep(0.5)
    raise AssertionError('Timeout: ' + description)


def main():
    handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                urllib.request.ProxyHandler({})]
    if os.environ.get('PANEL_TEST_CA'):
        handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ['PANEL_TEST_CA'])))
    opener = urllib.request.build_opener(*handlers)

    def post(path, data):
        page = opener.open(BASE + '/login').read().decode()
        token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        encoded = urllib.parse.urlencode(dict(csrf=token, **data)).encode()
        return opener.open(BASE + path, data=encoded).read()

    post('/login', dict(password=PASSWORD))
    body = post('/users', dict(name='e2e', gib='1', days='30')).decode()
    token = re.search(r'/s/([A-Za-z0-9_-]{43})', body).group(1)
    assert opener.open(BASE + '/s/' + token).status == 200
    profile = post('/users/e2e/profile', {})
    assert b'<key>' in profile and b'remote 192.0.2.1 1194' in profile
    Path('/tmp/e2e.ovpn').write_bytes(profile)
    cmd('ip', 'netns', 'add', 'ovp-test')
    cmd('ip', 'link', 'add', 'ovp-host', 'type', 'veth', 'peer', 'name', 'ovp-client')
    cmd('ip', 'link', 'set', 'ovp-client', 'netns', 'ovp-test')
    cmd('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'ovp-host')
    cmd('ip', 'link', 'set', 'ovp-host', 'up')
    cmd('ip', 'netns', 'exec', 'ovp-test', 'ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'ovp-client')
    cmd('ip', 'netns', 'exec', 'ovp-test', 'ip', 'link', 'set', 'ovp-client', 'up')
    cmd('ip', 'netns', 'exec', 'ovp-test', 'ip', 'link', 'set', 'lo', 'up')
    cmd('ip', 'netns', 'exec', 'ovp-test', 'ip', 'route', 'add', 'default', 'via', '192.0.2.1')
    q = Quotas('/var/lib/openvpn-panel/quota.sqlite')

    def start_client():
        Path('/tmp/e2e-client.log').unlink(missing_ok=True)
        return subprocess.Popen(['ip', 'netns', 'exec', 'ovp-test', 'openvpn', '--config', '/tmp/e2e.ovpn',
                                 '--log', '/tmp/e2e-client.log', '--connect-retry', '1', '1'])

    def no_open_session():
        with q._db() as db:
            return db.execute('SELECT count(*) FROM sessions WHERE closed=0').fetchone()[0] == 0

    def connected():
        p = Path('/tmp/e2e-client.log')
        return p.exists() and 'Initialization Sequence Completed' in p.read_text()

    client = start_client()
    try:
        wait_for(connected, 'real TLS tunnel established')
        wait_for(lambda: q.status('e2e').first_connected is not None, 'first activation persisted')
        # Generate real client traffic. Ping may be filtered upstream but transmitted
        # bytes must still appear in server management counters.
        subprocess.run(['ip', 'netns', 'exec', 'ovp-test', 'ping', '-c', '3', '-W', '1', '1.1.1.1'], check=False)
        wait_for(lambda: q.status('e2e').used_bytes > 100, 'live bidirectional-byte accounting')
        # Require actual HTTPS forwarding too (no reliance on client OS DNS hooks).
        github_ip = socket.gethostbyname('api.github.com')
        cmd('ip', 'netns', 'exec', 'ovp-test', 'curl', '--noproxy', '*', '--fail', '--max-time', '25',
            '--resolve', f'api.github.com:443:{github_ip}', 'https://api.github.com/zen')
        print('PASS: internet HTTPS routed through VPN', flush=True)
        q.update_limits('e2e', 1, 30)
        wait_for(lambda: q.status('e2e').reason == 'volume_exhausted', 'volume exhausted')
        wait_for(no_open_session, 'exhausted active connection terminated by server')
        # A fresh connect must be rejected by hook, not just dropped by polling.
        client.terminate()
        client.wait(timeout=10)
        client = start_client()
        time.sleep(8)
        assert not connected(), 'exhausted user was admitted'
        print('PASS: reconnect denied after volume exhaustion', flush=True)
        client.terminate()
        client.wait(timeout=10)
        q.update_limits('e2e', 1024**3, 30)
        client = start_client()
        wait_for(connected, 'renewed allowance reconnects')
        post('/users/e2e/toggle', dict(enabled='0'))
        wait_for(no_open_session, 'disabled active connection terminated by server')
        client.terminate()
        client.wait(timeout=10)
        q.set_enabled('e2e', True)
        client = start_client()
        wait_for(connected, 'manually enabled user reconnects')
        with q._db() as db:
            db.execute('UPDATE users SET first_connected=? WHERE name=?', (int(time.time())-31*86400, 'e2e'))
        wait_for(lambda: q.status('e2e').reason == 'expired', 'expiry reached')
        wait_for(no_open_session, 'expired active connection terminated by server')
        # Certificate rotation from web must revoke old certificate at TLS level.
        client.terminate()
        client.wait(timeout=10)
        with q._db() as db:
            db.execute('UPDATE users SET first_connected=? WHERE name=?', (int(time.time()), 'e2e'))
        new_profile = post('/users/e2e/profile', dict(action='rotate'))
        assert new_profile != profile
        client = start_client()  # old on-disk profile
        time.sleep(8)
        assert not connected(), 'revoked certificate connected'
        print('PASS: old profile rejected after certificate rotation', flush=True)
        client.terminate()
        client.wait(timeout=10)
        Path('/tmp/e2e.ovpn').write_bytes(new_profile)
        client = start_client()
        wait_for(connected, 'replacement certificate connects')
        cmd('/usr/local/sbin/openvpn-panelctl', 'backup', '/root/panel-ci-backup.tar.gz')
        import tarfile
        with tarfile.open('/root/panel-ci-backup.tar.gz') as archive:
            assert archive.getmember('var/lib/openvpn-panel/quota.sqlite').size > 0
            assert archive.getmember('etc/openvpn-panel/pki/ca.key').size > 0
        assert os.stat('/root/panel-ci-backup.tar.gz').st_mode & 0o077 == 0
        print('PASS: consistent private backup created', flush=True)
        cmd('/usr/local/sbin/openvpn-panelctl', 'restart')
        wait_for(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', 'openvpn-server@panel.service']).returncode == 0,
                 'maintenance restart restores VPN')
        cmd('systemctl', 'kill', '--signal=SIGKILL', 'openvpn-panel-accounting.service')
        wait_for(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', 'openvpn-server@panel.service']).returncode != 0,
                 'accounting failure stops OpenVPN (fail closed)')
    finally:
        if client.poll() is None:
            client.terminate()
            client.wait(timeout=10)
        subprocess.run(['ip', 'netns', 'del', 'ovp-test'], check=False)


if __name__ == '__main__':
    main()
