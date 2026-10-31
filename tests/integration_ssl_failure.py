"""Root-only disposable runner check: start managed Caddy from SSH mode.

No public certificate is expected for the reserved .invalid test domain. Shorten
only the wait deadline, not chain verification or any production safety check.
"""
import json
from pathlib import Path
import sys
sys.path.insert(0,'/opt/openvpn-panel')
from vpn import network_settings as n
from vpn.maintenance import atomic_json

assert n.current_domain() == ''
assert not n.active('caddy.service')
before={key:path.read_bytes() if path.exists() else None for key,path in n.paths().items()}
n.TLS_TIMEOUT=8
atomic_json(n.ROOT/'settings-pending.json',dict(operation='ssl-save',domain='panel.example.invalid',use_for_vpn=True,job_id='integration-ssh-failure'))
n.apply_pending()
state=json.loads((n.ROOT/'settings-state.json').read_text())
assert state['status']=='failed',state
assert state['diagnostic']=='tls_certificate',state
assert state['stage']=='certificate',state
assert state['error']=='apply_failed',state
for key,path in n.paths().items():
    assert (path.read_bytes() if path.exists() else None)==before[key],key
assert not n.active('caddy.service')
assert n.current_domain()==''
print('PASS: SSH-to-domain starts real Caddy, records certificate failure and restores original files/services',flush=True)
