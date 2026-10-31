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
    portal=opener.open(BASE+'/s/'+token).read()
    assert 'راهنمای اتصال'.encode() in portal
    assert b'id="tab-android"' in portal and b'id="tab-ios"' in portal and b'id="tab-windows"' in portal
    profile = post('/s/'+token+'/profile', {})
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
        import json
        def observed_online():
            data = json.loads(Path('/var/lib/openvpn-panel-status/online.json').read_text())
            return 'e2e' in data['users']
        wait_for(observed_online, 'online snapshot reflects real connected user')
        dashboard = opener.open(BASE + '/?q=e2e').read()
        for label in (b'CPU USAGE',b'RAM USAGE',b'SWAP USAGE',b'DISK USAGE',b'Total Users',b'Online'):
            assert label in dashboard
        print('PASS: resource dashboard and user search', flush=True)
        # Generate real client traffic. Ping may be filtered upstream but transmitted
        # bytes must still appear in server management counters.
        subprocess.run(['ip', 'netns', 'exec', 'ovp-test', 'ping', '-c', '3', '-W', '1', '1.1.1.1'], check=False)
        wait_for(lambda: q.status('e2e').used_bytes > 100, 'live bidirectional-byte accounting')
        # Require actual HTTPS forwarding too (no reliance on client OS DNS hooks).
        github_ip = socket.gethostbyname('github.com')
        cmd('ip', 'netns', 'exec', 'ovp-test', 'curl', '--noproxy', '*', '--fail', '--max-time', '25',
            '--retry', '2', '--retry-all-errors', '--retry-delay', '1',
            '--resolve', f'github.com:443:{github_ip}', '--output', '/tmp/vpn-internet-proof.txt', 'https://github.com/robots.txt')
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
        # SSL Management checks an already-trusted test certificate. Real ACME
        # issuance for a newly owned public DNS name cannot run on this runner.
        if BASE.startswith('https:'):
            host=urllib.parse.urlsplit(BASE).hostname
            post('/settings/ssl',dict(password=PASSWORD,confirm='1',domain=host,use_for_vpn='1'))
            def completed(operation):
                state=json.loads(Path('/etc/openvpn-panel/settings-state.json').read_text())
                if state.get('status')=='failed':
                    raise AssertionError('Settings job failed: '+state.get('error','unknown'))
                return state.get('status')=='completed' and state.get('operation')==operation
            wait_for(lambda: completed('ssl-save'),'SSL Management verifies HTTPS and commits domain',timeout=130)
            configured=post('/users/e2e/profile',{})
            assert ('remote '+host+' 1194').encode() in configured
            print('PASS: SSL domain appears in newly downloaded profiles',flush=True)
        def completed_vpn():
            state=json.loads(Path('/etc/openvpn-panel/settings-state.json').read_text())
            if state.get('status')=='failed':
                raise AssertionError('VPN settings job failed: '+state.get('error','unknown'))
            return state.get('status')=='completed' and state.get('operation')=='vpn-save'
        with Path('/etc/hosts').open('a') as hosts:
            hosts.write('\n192.0.2.1 vpn.example.invalid\n')
        activation=q.status('e2e').first_connected
        for chosen in ('tcp','udp'):
            client.terminate()
            client.wait(timeout=10)
            post('/settings/vpn',dict(password=PASSWORD,confirm='1',protocol=chosen,endpoint='vpn.example.invalid'))
            wait_for(completed_vpn,'VPN protocol applied: '+chosen,timeout=60)
            configured=post('/users/e2e/profile',{})
            expected=b'proto tcp4-client' if chosen=='tcp' else b'proto udp4'
            assert expected in configured and b'remote vpn.example.invalid 1194' in configured
            Path('/tmp/e2e.ovpn').write_bytes(configured)
            client=start_client()
            wait_for(connected,'real '+chosen.upper()+' connection through configured DNS endpoint')
            assert q.status('e2e').first_connected==activation
            cmd('ip','netns','exec','ovp-test','curl','--noproxy','*','--fail','--max-time','25',
                '--retry','2','--retry-all-errors','--resolve',f'github.com:443:{github_ip}',
                '--output','/tmp/vpn-protocol-proof.txt','https://github.com/robots.txt')
        print('PASS: UDP/TCP switching preserves users and serves internet on both transports',flush=True)
        # Web-managed encryption; no real Telegram token or public bot required.
        def copied_token():
            page=post('/users/e2e/link',{}).decode()
            return re.search(r'/s/([A-Za-z0-9_-]{43})',page).group(1)
        assert copied_token()==token
        assert copied_token()==token
        print('PASS: repeat copy does not rotate the subscription link',flush=True)
        migration_password = 'migration-test-passphrase-123'
        post('/backups/settings', dict(password=PASSWORD, interval='15', enabled='0',
                                      passphrase=migration_password, passphrase_repeat=migration_password, token='', chat_id=''))
        post('/backups/create', {})
        backup_page = opener.open(BASE + '/backups').read().decode()
        backup_name = re.search(r'backup-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}\.ovpnbak', backup_page).group(0)
        encrypted = opener.open(BASE + '/backups/download/' + backup_name).read()
        from vpn.backups import decrypt, MAGIC
        assert encrypted.startswith(MAGIC)
        assert decrypt(encrypted, migration_password)
        Path('/root/migration.ovpnbak').write_bytes(encrypted)
        Path('/root/migration-passphrase').write_text(migration_password)
        Path('/root/migration-passphrase').chmod(0o600)
        first = q.status('e2e').first_connected
        # Verify downtime controls never stop VPN or its accounting.
        old_pid = subprocess.check_output(['systemctl','show','--property=MainPID','--value','openvpn-panel']).strip()
        post('/system/web', dict(password=PASSWORD, confirm='1', action='restart'))
        def web_restarted():
            new_pid = subprocess.check_output(['systemctl','show','--property=MainPID','--value','openvpn-panel']).strip()
            if new_pid in (old_pid,b'0'):
                return False
            try:
                return opener.open(BASE + '/login', timeout=3).status == 200
            except Exception:
                return False
        wait_for(web_restarted, 'web restart completes with new serving process')
        cmd('systemctl','is-active','--quiet','openvpn-server@panel')
        post('/system/web', dict(password=PASSWORD, confirm='1', action='stop'))
        wait_for(lambda: subprocess.run(['systemctl','is-active','--quiet','openvpn-panel']).returncode != 0,
                 'web stop does not need root privileges in UI')
        cmd('systemctl','is-active','--quiet','openvpn-server@panel')
        cmd('systemctl','is-active','--quiet','openvpn-panel-accounting')
        cmd('/usr/local/sbin/openvpn-panelctl','web-start')
        print('PASS: encrypted web backups and isolated panel stop/restart', flush=True)
        client.terminate()
        client.wait(timeout=10)
        # Mutate current data, then restore the backup; new-host endpoint/settings must survive.
        q.create_user('must-disappear',100,1)
        endpoint_before = Path('/etc/openvpn-panel/vpn.json').read_bytes()
        env_before = Path('/etc/openvpn-panel/panel.env').read_bytes()
        cmd('/usr/local/sbin/openvpn-panelctl','restore','/root/migration.ovpnbak',
            '--passphrase-file','/root/migration-passphrase','--yes')
        assert [u.name for u in q.list_users()] == ['e2e']
        assert q.status('e2e').first_connected == first
        assert Path('/etc/openvpn-panel/vpn.json').read_bytes() == endpoint_before
        assert Path('/etc/openvpn-panel/panel.env').read_bytes() == env_before
        assert opener.open(BASE + '/s/' + token).status == 200
        assert copied_token()==token
        print('PASS: copied link decrypts as web user after restore',flush=True)
        client = start_client()
        wait_for(connected, 'restored certificate and users reconnect after migration')
        print('PASS: validated restore preserves new host settings and old user links', flush=True)
        cmd('/usr/local/sbin/openvpn-panelctl', 'backup', '/root/panel-ci-backup.tar.gz')
        import tarfile
        with tarfile.open('/root/panel-ci-backup.tar.gz') as archive:
            assert archive.getmember('var/lib/openvpn-panel/quota.sqlite').size > 0
            assert archive.getmember('etc/openvpn-panel/pki/ca.key').size > 0
        assert os.stat('/root/panel-ci-backup.tar.gz').st_mode & 0o077 == 0
        print('PASS: consistent private backup created', flush=True)
        post('/users/e2e/delete',dict(confirm='1',confirm_name='e2e'))
        wait_for(no_open_session,'deleted connected user is disconnected by accounting')
        assert not q.list_users()
        assert q.status_by_token(token) is None
        client.terminate()
        client.wait(timeout=10)
        client=start_client()
        time.sleep(8)
        assert not connected(),'deleted certificate reconnected'
        print('PASS: deletion hides user, invalidates link and blocks old certificate',flush=True)
        cmd('/usr/local/sbin/openvpn-panelctl', 'restart')
        wait_for(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', 'openvpn-server@panel.service']).returncode == 0,
                 'maintenance restart restores VPN')
        cmd('systemctl', 'kill', '--signal=SIGKILL', 'openvpn-panel-accounting.service')
        wait_for(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', 'openvpn-server@panel.service']).returncode != 0,
                 'accounting failure stops OpenVPN (fail closed)')
        cmd('/usr/local/sbin/openvpn-panelctl', 'restart')
        time.sleep(3)
        cmd('systemctl', 'kill', '--signal=SIGSTOP', 'openvpn-panel-accounting.service')
        wait_for(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', 'openvpn-server@panel.service']).returncode != 0,
                 'stalled accounting watchdog stops OpenVPN', timeout=35)
    finally:
        if client.poll() is None:
            client.terminate()
            client.wait(timeout=10)
        subprocess.run(['ip', 'netns', 'del', 'ovp-test'], check=False)


if __name__ == '__main__':
    main()
