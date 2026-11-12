import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock
from vpn.dual import secondary_config,sync_secondary,install_network
from vpn.collector import CombinedManagement,enforce
from vpn.hook import address
from quota import Quotas
from metrics import connection_transports
import json

PRIMARY='''proto udp4
dev tun-panel
server 10.87.0.0 255.255.255.0
server-ipv6 fd42:87:87::/64
management /run/openvpn-panel/management.sock unix
allow-compression no
fast-io
'''

class DualTests(TestCase):
    def test_derived_config_and_firewall_isolate_secondary(self):
        text=secondary_config(PRIMARY)
        self.assertIn('dev tun-panel-tcp',text)
        self.assertIn('10.88.0.0',text)
        self.assertIn('setenv PANEL_TRANSPORT tcp',text)
        self.assertIn('management-tcp.sock',text)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'secondary.conf'
            sync_secondary(PRIMARY,True,path)
            self.assertEqual(path.read_text(),text)
            sync_secondary(PRIMARY,False,path)
            self.assertFalse(path.exists())
            script=Path(temp)/'openvpn-panel-network'
            script.write_text('tun-panel 10.87.0.0/24 OVP_PANEL_FWD DROP')
            install_network(script)
            self.assertEqual((script.with_name('openvpn-panel-network-tcp')).read_text(),'tun-panel-tcp 10.88.0.0/24 OVP_PANEL_TCP_FWD DROP')

    def test_shared_cap_counters_and_per_listener_kill(self):
        with tempfile.TemporaryDirectory() as temp:
            q=Quotas(str(Path(temp)/'db'))
            q.create_user('alice',100,30,max_connections=2)
            q.vpn_connect('alice','1.2.3.4:1234')
            q.vpn_connect('alice','tcp@1.2.3.4:1234')
            with self.assertRaisesRegex(PermissionError,'connection_limit'): q.vpn_connect('alice','third')
            udp,tcp=Mock(),Mock()
            udp.status.return_value=[('alice','1.2.3.4:1234',30,30,0)]
            tcp.status.return_value=[('alice','1.2.3.4:1234',30,30,0)]
            combined=CombinedManagement(udp,tcp)
            self.assertEqual(enforce(q,combined),[])
            udp.kill_client.assert_called_once_with(0)
            tcp.kill_client.assert_called_once_with(0)
            self.assertEqual(q.status('alice').used_bytes,120)
            self.assertEqual(address(dict(trusted_ip='1.2.3.4',trusted_port='1234',PANEL_TRANSPORT='tcp')),'tcp@1.2.3.4:1234')

    def test_only_fresh_verified_alternatives_are_advertised(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'snapshot'
            path.write_text(json.dumps(dict(updated_at=100,transports=['udp','tcp'])))
            self.assertEqual(connection_transports(path,101),['udp','tcp'])
            self.assertEqual(connection_transports(path,116),[])
