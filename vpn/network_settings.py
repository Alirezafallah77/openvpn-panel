"""Fixed-path, root-only SSL and OpenVPN settings transactions.

The web broker only validates/queues. A separate transient root unit edits files;
it never accepts paths, shell text, arbitrary units or certificate commands.
"""
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import time
import uuid
from vpn.maintenance import atomic_json, read_json

ROOT = Path('/etc/openvpn-panel')
SERVER = Path('/etc/openvpn/server/panel.conf')
CADDY = Path('/etc/caddy/Caddyfile')
TLS_TIMEOUT = 100


def domain(value):
    if type(value) is not str:
        raise ValueError('Invalid domain')
    value = value.strip().lower().rstrip('.')
    if not value.isascii() or len(value) > 253 or '.' not in value or value.split('.')[-1].isdigit():
        raise ValueError('Use a fully qualified ASCII DNS name')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('SSL requires a DNS name, not an IP')
    if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.')):
        raise ValueError('Invalid domain labels')
    return value


def endpoint(value):
    if type(value) is not str:
        raise ValueError('Invalid endpoint')
    value = value.strip()
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return domain(value)


def protocol(value):
    if value not in ('udp', 'tcp'):
        raise ValueError('Protocol must be UDP or TCP')
    return value


def environment():
    values = {}
    for line in (ROOT/'panel.env').read_text().splitlines():
        if line.startswith('PANEL_') and '=' in line:
            name, value = line.split('=', 1)
            values[name] = value.strip().strip("'\"")
    return values


def load_config():
    config = json.loads((ROOT/'vpn.json').read_text())
    if 'protocol' not in config:
        config['protocol'] = 'tcp' if re.search(r'^proto\s+tcp', SERVER.read_text(), re.M) else 'udp'
    return config


def current_domain():
    env = environment()
    if env.get('PANEL_LOCAL_HTTP') == '1':
        return ''
    try:
        return domain(env.get('PANEL_HOST', ''))
    except ValueError:
        return ''


@contextmanager
def locked(blocking=True):
    with (ROOT/'settings.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=30)


def systemctl(*args):
    command('/usr/bin/systemctl', *args)


def active(unit):
    return subprocess.run(['/usr/bin/systemctl','is-active','--quiet',unit],
                          capture_output=True, timeout=5).returncode == 0


def write(path, text, mode=0o600):
    tmp = path.with_name(path.name+'.panel-new')
    with tmp.open('w') as out:
        os.chmod(tmp, mode)
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    tmp.replace(path)


def managed_caddy(text, host):
    # Claim only the exact single-site templates emitted by our old installer.
    text = re.sub(r'#.*', '', text)
    text = re.sub(r'\s+', '', text)
    return text in (host+'{reverse_proxy127.0.0.1:8000}',
                    host+'{tlsinternalreverse_proxy127.0.0.1:8000}')


def bootstrap(allow_default=False):
    """Only installer/upgrade may establish ownership of Caddy's file."""
    if not (ROOT/'caddy-owned').exists():
        host = current_domain()
        if allow_default or (host and CADDY.is_file() and managed_caddy(CADDY.read_text(), host)):
            write(ROOT/'caddy-owned', 'Managed exclusively by OpenVPN Panel\n')
    conf = load_config()
    atomic_json(ROOT/'vpn.json', conf)


def probe_tls(host, timeout=2):
    """Verify hostname/chain over loopback; never connect to a user-supplied IP."""
    try:
        host = domain(host)
        context = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1',443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                certificate = secure.getpeercert()
                secure.sendall(f'GET /login HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode('ascii'))
                line = secure.recv(4096).split(b'\r\n',1)[0]
        return dict(valid=True, expires=int(ssl.cert_time_to_seconds(certificate['notAfter'])),
                    issuer=', '.join(value for group in certificate.get('issuer',()) for _,value in group),
                    http_ok=bool(re.match(rb'HTTP/1\.[01] 200(?: |$)',line)))
    except (OSError, ValueError, ssl.SSLError):
        return dict(valid=False, expires=None, issuer='', http_ok=False)


def public_settings():
    conf, host = load_config(), current_domain()
    return dict(endpoint=conf['endpoint'], protocol=conf['protocol'], port=conf['port'],
                domain=host, caddy_managed=(ROOT/'caddy-owned').is_file(),
                caddy_installed=bool(shutil.which('caddy')),
                tls=probe_tls(host, timeout=1) if host else dict(valid=False, expires=None,issuer='',http_ok=False),
                job=read_json(ROOT/'settings-state.json', {}))


def queue(message):
    op = message.get('operation')
    if op == 'ssl-save' and set(message) == {'operation','domain','use_for_vpn'}:
        request = dict(operation=op, domain=domain(message['domain']), use_for_vpn=message['use_for_vpn'])
        if type(request['use_for_vpn']) is not bool or not (ROOT/'caddy-owned').is_file() or not shutil.which('caddy'):
            raise ValueError('Caddy is not managed by this installation')
    elif op == 'vpn-save' and set(message) == {'operation','protocol','endpoint'}:
        request = dict(operation=op, protocol=protocol(message['protocol']), endpoint=endpoint(message['endpoint']))
    else:
        raise ValueError('Unknown settings fields')
    with locked(blocking=False):
        state = read_json(ROOT/'settings-state.json', {})
        if state.get('status') in ('queued','running') and time.time()-state.get('updated_at',0) < 300:
            raise ValueError('Settings change already in progress')
        job_id = uuid.uuid4().hex
        request['job_id'] = job_id
        atomic_json(ROOT/'settings-pending.json', request)
        atomic_json(ROOT/'settings-state.json', dict(status='queued', operation=op, updated_at=int(time.time()),job_id=job_id))
        try:
            command('/usr/bin/systemd-run','--quiet','--collect', '--unit=openvpn-panel-settings-'+job_id,
                    '--on-active=3s','--timer-property=AccuracySec=1s',
                    '--property=RuntimeMaxSec=240', '/usr/local/sbin/openvpn-panelctl','apply-settings')
        except Exception:
            atomic_json(ROOT/'settings-state.json',dict(status='failed',error='queue_failed',updated_at=int(time.time())))
            (ROOT/'settings-pending.json').unlink(missing_ok=True)
            raise
    return dict(queued=True, job_id=job_id, domain=request.get('domain',''))


def snapshot():
    saved = dict(files={}, caddy_active=active('caddy.service'),
                 caddy_enabled=subprocess.run(['/usr/bin/systemctl','is-enabled','--quiet','caddy.service'],capture_output=True,timeout=5).returncode==0)
    for key,path in paths().items():
        saved['files'][key] = path.read_text() if path.exists() else None
    atomic_json(ROOT/'settings-rollback.json', saved)
    return saved


def paths():
    return dict(env=ROOT/'panel.env', vpn=ROOT/'vpn.json', server=SERVER, caddy=CADDY)


def restore_files(saved):
    for key,path in paths().items():
        data = saved['files'][key]
        if data is None:
            path.unlink(missing_ok=True)
        else:
            write(path,data,0o644 if key=='caddy' else 0o600)


def restart_vpn():
    systemctl('stop','openvpn-server@panel.service')
    systemctl('stop','openvpn-panel-accounting.service')
    systemctl('reset-failed','openvpn-server@panel.service','openvpn-panel-accounting.service')
    systemctl('start','openvpn-server@panel.service')
    end = time.monotonic()+20
    while time.monotonic() < end:
        try:
            if 0 <= time.time()-Path('/run/openvpn-panel/heartbeat').stat().st_mtime <= 10:
                return
        except FileNotFoundError:
            pass
        time.sleep(0.2)
    raise RuntimeError('Accounting did not become ready')


def restart_web():
    systemctl('reset-failed','openvpn-panel.service')
    systemctl('restart','openvpn-panel.service')


def caddy_apply(saved):
    command('caddy','validate','--config',str(CADDY))
    systemctl('reset-failed','caddy.service')
    if active('caddy.service'):
        systemctl('reload','caddy.service')
    else:
        systemctl('start','caddy.service')


def wait_tls(host, http=False):
    end = time.monotonic()+TLS_TIMEOUT
    while time.monotonic() < end:
        result = probe_tls(host)
        if result['valid'] and (not http or result['http_ok']):
            return result
        time.sleep(2)
    raise RuntimeError('TLS certificate or panel HTTPS not ready')


def apply_ssl(request, saved):
    host, old = domain(request['domain']), current_domain()
    if not (ROOT/'caddy-owned').is_file():
        raise ValueError('Unmanaged Caddy')
    # Preserve the already-managed issuer on a no-op domain update. This also
    # supports an administrator-installed private CA without silently replacing it.
    if old != host or not CADDY.is_file():
        hosts = ', '.join(dict.fromkeys([h for h in (old,host) if h]))
        write(CADDY, hosts+' {\n    reverse_proxy 127.0.0.1:8000\n}\n',0o644)
    caddy_apply(saved)
    wait_tls(host)  # Certificate must verify before switching panel cookies/hosts.
    with (ROOT/'pki/lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        lines = [line for line in (ROOT/'panel.env').read_text().splitlines()
                 if not line.startswith(('PANEL_HOST=','PANEL_EXTRA_HOSTS=','PANEL_LOCAL_HTTP='))]
        alias = old if old and old!=host else environment().get('PANEL_EXTRA_HOSTS','localhost')
        lines.extend(['PANEL_HOST='+host,'PANEL_EXTRA_HOSTS='+alias])
        write(ROOT/'panel.env','\n'.join(lines)+'\n')
        if request['use_for_vpn']:
            conf = load_config()
            conf['endpoint'] = host
            atomic_json(ROOT/'vpn.json',conf)
        restart_web()
    wait_tls(host,http=True)
    systemctl('enable','caddy.service')


def apply_vpn(request):
    chosen, remote = protocol(request['protocol']), endpoint(request['endpoint'])
    with (ROOT/'pki/lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        conf = load_config()
        text = SERVER.read_text()
        if len(re.findall(r'^proto\s+\S+\s*$', text, re.M)) != 1:
            raise ValueError('Unexpected OpenVPN protocol configuration')
        text = re.sub(r'^proto\s+\S+\s*$', 'proto '+('udp4' if chosen=='udp' else 'tcp4-server'), text,count=1,flags=re.M)
        write(SERVER,text)
        conf.update(protocol=chosen, endpoint=remote)
        atomic_json(ROOT/'vpn.json',conf)
        restart_vpn()


def apply_pending():
    with locked():
        request = read_json(ROOT/'settings-pending.json',{})
        if request.get('operation') not in ('ssl-save','vpn-save'):
            raise ValueError('No queued settings change')
        operation = request['operation']
        atomic_json(ROOT/'settings-state.json',dict(status='running',operation=operation,job_id=request['job_id'],updated_at=int(time.time())))
        saved = snapshot()
        try:
            if operation=='ssl-save': apply_ssl(request,saved)
            else: apply_vpn(request)
        except Exception:
            rollback_ok = True
            try:
                with (ROOT/'pki/lock').open('a') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX)
                    restore_files(saved)
                    systemctl('enable' if saved['caddy_enabled'] else 'disable','caddy.service')
                    if operation=='ssl-save':
                        if saved['caddy_active']: caddy_apply(saved)
                        else: systemctl('stop','caddy.service')
                        restart_web()
                    else: restart_vpn()
            except Exception:
                rollback_ok = False
            atomic_json(ROOT/'settings-state.json',dict(status='failed',operation=operation,
                error='apply_failed' if rollback_ok else 'rollback_failed',updated_at=int(time.time())))
        else:
            atomic_json(ROOT/'settings-state.json',dict(status='completed',operation=operation,updated_at=int(time.time())))
        finally:
            (ROOT/'settings-pending.json').unlink(missing_ok=True)


def rollback():
    with locked():
        saved = read_json(ROOT/'settings-rollback.json',{})
        if set(saved) != {'files','caddy_active','caddy_enabled'}:
            raise ValueError('No rollback snapshot')
        (ROOT/'settings-pending.json').unlink(missing_ok=True)
        with (ROOT/'pki/lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            restore_files(saved)
            systemctl('enable' if saved['caddy_enabled'] else 'disable','caddy.service')
            if saved['caddy_active']: caddy_apply(saved)
            else: systemctl('stop','caddy.service')
            restart_vpn()
            restart_web()
        atomic_json(ROOT/'settings-state.json',dict(status='rolled_back',updated_at=int(time.time())))
