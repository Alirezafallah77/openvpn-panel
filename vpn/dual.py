"""Derived secondary transport: separate tunnel/socket, shared PKI and quota DB."""
from pathlib import Path
import re
from vpn.performance import tune_server

SECONDARY=Path('/etc/openvpn/server/panel-tcp.conf')
TCP_SOCKET='/run/openvpn-panel/management-tcp.sock'


def secondary_config(primary):
    replacements={r'^proto\s+\S+':'proto tcp4-server',r'^dev\s+\S+':'dev tun-panel-tcp',
        r'^server\s+.*':'server 10.88.0.0 255.255.255.0',
        r'^server-ipv6\s+.*':'server-ipv6 fd42:88:88::/64',
        r'^management\s+.*':'management '+TCP_SOCKET+' unix'}
    for pattern,value in replacements.items():
        primary,count=re.subn(pattern,value,primary,flags=re.M)
        if count!=1: raise ValueError('Cannot derive secondary OpenVPN configuration')
    return tune_server(primary)+'setenv PANEL_TRANSPORT tcp\n'


def sync_secondary(primary,enabled,path=SECONDARY):
    if not enabled:
        path.unlink(missing_ok=True)
        return
    text=secondary_config(primary)
    temporary=path.with_suffix('.new')
    temporary.write_text(text)
    temporary.chmod(0o600)
    temporary.replace(path)


def install_network(source=Path('/usr/local/sbin/openvpn-panel-network')):
    # Same private-network isolation and NAT rules, separate dedicated chain.
    text=source.read_text().replace('tun-panel','tun-panel-tcp').replace('10.87.0.0/24','10.88.0.0/24').replace('OVP_PANEL_FWD','OVP_PANEL_TCP_FWD')
    path=source.with_name('openvpn-panel-network-tcp')
    path.write_text(text)
    path.chmod(0o755)
