"""Fixed-path, root-only SSL and OpenVPN settings transactions.

The web broker only validates/queues. A separate transient root unit edits files;
it never accepts paths, shell text, arbitrary units or certificate commands.
"""
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import time
import uuid
import urllib.request
from panel_web import admin_path, public_port
from vpn.maintenance import atomic_json, read_json

ROOT = Path('/etc/openvpn-panel')
SERVER = Path('/etc/openvpn/server/panel.conf')
CADDY = Path('/etc/caddy/Caddyfile')
TLS_TIMEOUT = 180
HTTP_TIMEOUT = 30


class SettingsFailure(RuntimeError):
    """Stable public diagnostic code; never expose subprocess output to the web."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def stage(name):
    state = read_json(ROOT/'settings-state.json', {})
    state.update(stage=name, updated_at=int(time.time()))
    atomic_json(ROOT/'settings-state.json', state)


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


def reset_failed(unit):
    # Inactive, disabled units may be garbage-collected by systemd. Calling
    # reset-failed on such a unit returns 1 ("not loaded") before start can load it.
    # Only failed units require a reset (including start-limit recovery).
    if subprocess.run(['/usr/bin/systemctl','is-failed','--quiet',unit],
                      capture_output=True,timeout=5).returncode == 0:
        systemctl('reset-failed',unit)


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


def probe_tls(host, timeout=2, port=None, prefix=None):
    """Verify hostname/chain over loopback; never connect to a user-supplied IP."""
    try:
        host = domain(host)
        env=environment()
        port=public_port(env.get('PANEL_PUBLIC_PORT','443')) if port is None else public_port(port)
        prefix=admin_path(env.get('PANEL_ADMIN_PATH','')) if prefix is None else admin_path(prefix)
        context = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1',port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                certificate = secure.getpeercert()
                result = dict(valid=True, expires=int(ssl.cert_time_to_seconds(certificate['notAfter'])),
                    issuer=', '.join(value for group in certificate.get('issuer',()) for _,value in group),
                    http_ok=False)
                # An HTTP timeout must not erase a successfully verified TLS chain.
                try:
                    secure.sendall(f'GET {prefix}/login HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n'.encode('ascii'))
                    line = b''
                    while b'\r\n' not in line and len(line) < 4096:
                        data = secure.recv(512)
                        if not data: break
                        line += data
                    result['http_ok'] = bool(re.match(rb'HTTP/1\.[01] 200(?: |$)', line.split(b'\r\n',1)[0]))
                except OSError:
                    pass
                return result
    except (OSError, ValueError, ssl.SSLError):
        return dict(valid=False, expires=None, issuer='', http_ok=False)


def public_settings():
    conf, host = load_config(), current_domain()
    return dict(endpoint=conf['endpoint'], protocol=conf['protocol'], port=conf['port'],
                domain=host, public_port=int(environment().get('PANEL_PUBLIC_PORT','443')), admin_path=environment().get('PANEL_ADMIN_PATH',''), caddy_managed=(ROOT/'caddy-owned').is_file(),
                caddy_installed=bool(shutil.which('caddy')),
                tls=probe_tls(host, timeout=1) if host else dict(valid=False, expires=None,issuer='',http_ok=False),
                job=read_json(ROOT/'settings-state.json', {}))


def queue(message):
    op = message.get('operation')
    if op == 'ssl-save' and set(message) == {'operation','domain','use_for_vpn'}:
        request = dict(operation=op, domain=domain(message['domain']), use_for_vpn=message['use_for_vpn'])
        if type(request['use_for_vpn']) is not bool or not (ROOT/'caddy-owned').is_file() or not shutil.which('caddy'):
            raise ValueError('Caddy is not managed by this installation')
    elif op == 'panel-save' and set(message)=={'operation','public_port','admin_path'}:
        chosen=public_port(message['public_port'])
        if chosen==int(load_config()['port']): raise ValueError('Port conflicts with OpenVPN')
        if not current_domain() and chosen!=int(environment().get('PANEL_PUBLIC_PORT','443')):
            raise ValueError('Enable SSL before changing the public HTTPS port')
        if current_domain() and not (ROOT/'caddy-owned').is_file(): raise ValueError('Unmanaged Caddy')
        request=dict(operation=op,public_port=chosen,admin_path=admin_path(message['admin_path']))
    elif op == 'vpn-save' and set(message) == {'operation','protocol','endpoint'}:
        request = dict(operation=op, protocol=protocol(message['protocol']), endpoint=endpoint(message['endpoint']))
    else:
        raise ValueError('Unknown settings fields')
    with locked(blocking=False):
        state = read_json(ROOT/'settings-state.json', {})
        if state.get('status') in ('queued','running') and time.time()-state.get('updated_at',0) < 480:
            raise ValueError('Settings change already in progress')
        job_id = uuid.uuid4().hex
        request['job_id'] = job_id
        atomic_json(ROOT/'settings-pending.json', request)
        atomic_json(ROOT/'settings-state.json', dict(status='queued', operation=op, updated_at=int(time.time()),job_id=job_id))
        try:
            command('/usr/bin/systemd-run','--quiet','--collect', '--unit=openvpn-panel-settings-'+job_id,
                    '--on-active=3s','--timer-property=AccuracySec=1s',
                    '--property=RuntimeMaxSec=420', '/usr/local/sbin/openvpn-panelctl','apply-settings')
        except Exception:
            atomic_json(ROOT/'settings-state.json',dict(status='failed',error='queue_failed',updated_at=int(time.time())))
            (ROOT/'settings-pending.json').unlink(missing_ok=True)
            raise
    return dict(queued=True, job_id=job_id, domain=request.get('domain',''),
                public_port=public_port(environment().get('PANEL_PUBLIC_PORT','443')),
                admin_path=admin_path(environment().get('PANEL_ADMIN_PATH','')))


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
    reset_failed('openvpn-panel.service')
    systemctl('restart','openvpn-panel.service')


def caddy_apply(saved):
    try:
        command('caddy','validate','--config',str(CADDY))
    except Exception as error:
        # Validation runs as a CLI, so its captured stderr is NOT in caddy.service's journal.
        # Log only this fixed Caddy command's output in the root worker journal, never the web.
        detail = getattr(error, 'stderr', None)
        if detail:
            logging.error('Caddy validation stderr: %s', detail[:8192])
        raise SettingsFailure('caddy_validate') from error
    try:
        reset_failed('caddy.service')
        if active('caddy.service'):
            systemctl('reload','caddy.service')
        else:
            systemctl('start','caddy.service')
    except Exception as error:
        raise SettingsFailure('caddy_start') from error


def wait_tls(host, http=False, **options):
    end = time.monotonic()+(HTTP_TIMEOUT if http else TLS_TIMEOUT)
    while time.monotonic() < end:
        result = probe_tls(host,**options)
        if result['valid'] and (not http or result['http_ok']):
            return result
        time.sleep(2)
    raise SettingsFailure('panel_https' if http else 'tls_certificate')


def old_ports():
    text=environment().get('PANEL_OLD_PUBLIC_PORTS','')
    return [public_port(p) for p in text.split(',') if p]


def render_caddy(hosts, port, aliases, internal=False):
    """Old ports serve only existing public subscriptions, never admin routes."""
    hosts=[domain(h) for h in hosts]
    tls='    tls internal\n' if internal else ''
    def addresses(p): return ', '.join(h+(':'+str(p) if p!=443 else '') for h in hosts)
    text='# OpenVPN Panel web access v1\n'+addresses(port)+' {\n'+tls+'    reverse_proxy 127.0.0.1:8000\n}\n'
    for p in aliases:
        if p==port: continue
        text+=addresses(p)+' {\n'+tls+'    @public path /s/* /static/* /preferences\n    handle @public {\n        reverse_proxy 127.0.0.1:8000\n    }\n    handle {\n        respond 404\n    }\n}\n'
    return text


def wait_local_login(prefix):
    end=time.monotonic()+HTTP_TIMEOUT
    host=environment().get('PANEL_HOST','localhost')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic()<end:
        try:
            req=urllib.request.Request('http://127.0.0.1:8000'+prefix+'/login',headers={'Host':host})
            with opener.open(req,timeout=2) as response:
                if response.status==200: return
        except OSError: pass
        time.sleep(1)
    raise SettingsFailure('panel_https')


def apply_panel(request,saved):
    env=environment()
    host=current_domain()
    port=public_port(request['public_port'])
    prefix=admin_path(request['admin_path'])
    previous=public_port(env.get('PANEL_PUBLIC_PORT','443'))
    aliases=list(dict.fromkeys(old_ports()+([previous] if previous!=port else [])))
    aliases=[p for p in aliases if p!=port]
    if len(aliases)>8: raise ValueError('Too many retained public ports; inspect from SSH')
    if host:
        if not (ROOT/'caddy-owned').is_file(): raise ValueError('Unmanaged Caddy')
        stage('caddy')
        if port!=previous:
            text=CADDY.read_text()
            if not (text.startswith('# OpenVPN Panel web access v1') or managed_caddy(text,host)):
                # Our SSL switch may have preserved a former HTTPS hostname.
                compact=re.sub(r'\s+','',re.sub(r'#.*','',text))
                if not re.fullmatch(r'[a-z0-9.,:-]+\{(?:tlsinternal)?reverse_proxy127\.0\.0\.1:8000\}',compact):
                    raise ValueError('Caddy config is not a supported managed template')
            hosts=[host]+[h for h in env.get('PANEL_EXTRA_HOSTS','').split(',') if h not in ('localhost','127.0.0.1','',host)]
            write(CADDY,render_caddy(hosts,port,aliases,internal=bool(re.search(r'^\s*tls internal\s*$',text,re.M))),0o644)
        caddy_apply(saved)
        wait_tls(host,port=port,prefix=env.get('PANEL_ADMIN_PATH',''))
    elif port!=previous: raise ValueError('SSL required')
    with (ROOT/'pki/lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        lines=[line for line in (ROOT/'panel.env').read_text().splitlines() if not line.startswith(('PANEL_PUBLIC_PORT=','PANEL_ADMIN_PATH=','PANEL_OLD_PUBLIC_PORTS='))]
        lines+=['PANEL_PUBLIC_PORT='+str(port),'PANEL_ADMIN_PATH='+prefix,'PANEL_OLD_PUBLIC_PORTS='+','.join(map(str,aliases))]
        write(ROOT/'panel.env','\n'.join(lines)+'\n')
        stage('web_restart')
        restart_web()
    if host:
        stage('https_check')
        wait_tls(host,http=True,port=port,prefix=prefix)
        systemctl('enable','caddy.service')
    else: wait_local_login(prefix)


def apply_ssl(request, saved):
    host, old = domain(request['domain']), current_domain()
    if not (ROOT/'caddy-owned').is_file():
        raise ValueError('Unmanaged Caddy')
    # Preserve the already-managed issuer on a no-op domain update. This also
    # supports an administrator-installed private CA without silently replacing it.
    if old != host or not CADDY.is_file():
        hosts = ', '.join(dict.fromkeys([h for h in (old,host) if h]))
        write(CADDY, render_caddy(hosts.split(', '),int(environment().get('PANEL_PUBLIC_PORT','443')),old_ports()),0o644)
    stage('caddy')
    caddy_apply(saved)
    stage('certificate')
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
        stage('web_restart')
        try:
            restart_web()
        except Exception as error:
            raise SettingsFailure('web_restart') from error
    stage('https_check')
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
        if request.get('operation') not in ('ssl-save','vpn-save','panel-save'):
            raise ValueError('No queued settings change')
        operation = request['operation']
        atomic_json(ROOT/'settings-state.json',dict(status='running',operation=operation,job_id=request['job_id'],updated_at=int(time.time())))
        saved = snapshot()
        try:
            if operation=='ssl-save': apply_ssl(request,saved)
            elif operation=='panel-save': apply_panel(request,saved)
            else: apply_vpn(request)
        except Exception as failure:
            diagnostic = failure.code if isinstance(failure, SettingsFailure) else 'unexpected'
            failed_stage = read_json(ROOT/'settings-state.json',{}).get('stage','vpn')
            logging.exception('Network settings failed: operation=%s stage=%s code=%s', operation, failed_stage, diagnostic)
            rollback_ok = True
            try:
                with (ROOT/'pki/lock').open('a') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX)
                    restore_files(saved)
                    systemctl('enable' if saved['caddy_enabled'] else 'disable','caddy.service')
                    if operation in ('ssl-save','panel-save'):
                        if saved['caddy_active']: caddy_apply(saved)
                        else: systemctl('stop','caddy.service')
                        restart_web()
                    else: restart_vpn()
            except Exception:
                rollback_ok = False
            atomic_json(ROOT/'settings-state.json',dict(status='failed',operation=operation,
                error='apply_failed' if rollback_ok else 'rollback_failed', diagnostic=diagnostic, stage=failed_stage, updated_at=int(time.time())))
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
