"""Conservative Linux OpenVPN transport tuning, with no crypto/MTU changes."""
import re

BEGIN = '# BEGIN openvpn-panel transport tuning'
END = '# END openvpn-panel transport tuning'


def tune_server(text):
    protocols=re.findall(r'^proto[ \t]+(\S+)[ \t]*$',text,re.M)
    if len(protocols)!=1 or protocols[0] not in ('udp','udp4','udp6','tcp-server','tcp4-server','tcp6-server'):
        raise ValueError('Unsupported server protocol')
    # Only replace our marked block, preserving operator settings outside it.
    if text.count(BEGIN)!=text.count(END) or text.count(BEGIN)>1:
        raise ValueError('Invalid managed transport block')
    text,count=re.subn(r'^'+re.escape(BEGIN)+r'\n.*?^'+re.escape(END)+r'\n?', '',text,flags=re.M|re.S)
    if BEGIN in text or END in text:
        raise ValueError('Invalid managed transport block order')
    # fast-io avoids an extra readiness check on Linux's nonblocking UDP/TUN
    # writes. TCP uses NODELAY to avoid Nagle delays, never fast-io.
    option='fast-io' if protocols[0].startswith('udp') else 'tcp-nodelay'
    return text.rstrip()+'\n'+BEGIN+'\n'+option+'\n'+END+'\n'
