import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from vpn import network_settings as n


class NetworkSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root/'pki').mkdir()
        self.server = self.root/'server.conf'
        self.caddy = self.root/'Caddyfile'
        self.server.write_text('port 1194\nproto udp4\ndev tun-panel\n')
        self.caddy.write_text('old.example.com {\n reverse_proxy 127.0.0.1:8000\n}\n')
        (self.root/'panel.env').write_text("PANEL_HOST=old.example.com\nPANEL_SECRET=keep-secret\nPANEL_PASSWORD_HASH='hash$with$dollars'\n")
        (self.root/'vpn.json').write_text('{"endpoint":"192.0.2.1","port":1194,"protocol":"udp"}')
        (self.root/'caddy-owned').write_text('managed')
        self.patches = [patch.object(n,'ROOT',self.root), patch.object(n,'SERVER',self.server),
            patch.object(n,'CADDY',self.caddy), patch.object(n,'command',return_value=Mock(returncode=0)),
            patch.object(n,'active',return_value=False), patch.object(n.subprocess,'run',return_value=Mock(returncode=0)),
            patch.object(n,'restart_vpn'), patch.object(n,'restart_web'), patch.object(n,'wait_tls'),
            patch.object(n.shutil,'which',return_value='/usr/bin/caddy')]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def test_panel_port_prefix_transaction_preserves_vpn_and_public_aliases(self):
        original_server=self.server.read_text()
        original_vpn=(self.root/'vpn.json').read_text()
        n.queue(dict(operation='panel-save',public_port=5000,admin_path='/private'))
        n.apply_pending()
        self.assertEqual(n.read_json(self.root/'settings-state.json',{})['status'],'completed')
        env=n.environment()
        self.assertEqual(env['PANEL_PUBLIC_PORT'],'5000')
        self.assertEqual(env['PANEL_ADMIN_PATH'],'/private')
        self.assertEqual(env['PANEL_OLD_PUBLIC_PORTS'],'443')
        self.assertEqual(env['PANEL_SECRET'],'keep-secret')
        self.assertEqual(self.server.read_text(),original_server)
        self.assertEqual((self.root/'vpn.json').read_text(),original_vpn)
        n.restart_vpn.assert_not_called()
        n.wait_tls.assert_any_call('old.example.com',http=True,port=5000,prefix='/private')
        caddy=self.caddy.read_text()
        self.assertIn('old.example.com:5000 {',caddy)
        self.assertIn('@public path /s/* /static/* /preferences',caddy)
        self.assertIn('respond 404',caddy)
        # Change back to a retained port; do not create duplicate site blocks.
        n.queue(dict(operation='panel-save',public_port=443,admin_path='/other'))
        n.apply_pending()
        self.assertEqual(n.environment()['PANEL_OLD_PUBLIC_PORTS'],'5000')
        self.assertEqual(self.caddy.read_text().count('old.example.com {'),1)

    def test_panel_failed_health_check_restores_environment_and_caddy(self):
        before_env=(self.root/'panel.env').read_text()
        before_caddy=self.caddy.read_text()
        n.queue(dict(operation='panel-save',public_port=5000,admin_path='/private'))
        n.wait_tls.side_effect=[None,n.SettingsFailure('panel_https')]
        n.apply_pending()
        result=n.read_json(self.root/'settings-state.json',{})
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['error'],'apply_failed')
        self.assertEqual(result['diagnostic'],'panel_https')
        self.assertEqual((self.root/'panel.env').read_text(),before_env)
        self.assertEqual(self.caddy.read_text(),before_caddy)
        n.restart_vpn.assert_not_called()

    def test_panel_validation_ssl_requirement_and_port_conflict(self):
        for port in (1194,8000,2019,80,65536,True):
            with self.assertRaises(ValueError): n.queue(dict(operation='panel-save',public_port=port,admin_path=''))
        (self.root/'panel.env').write_text('PANEL_LOCAL_HTTP=1\nPANEL_SECRET=keep-secret\n')
        with self.assertRaises(ValueError): n.queue(dict(operation='panel-save',public_port=5000,admin_path=''))
        n.queue(dict(operation='panel-save',public_port=443,admin_path='/ssh-panel'))
        with patch.object(n,'wait_local_login') as check:
            n.apply_pending()
            check.assert_called_once_with('/ssh-panel')
        self.assertEqual(n.environment()['PANEL_ADMIN_PATH'],'/ssh-panel')

    def test_strict_domain_endpoint_protocol_validation(self):
        self.assertEqual(n.domain(' PANEL.Example.com. '),'panel.example.com')
        self.assertEqual(n.endpoint('192.0.2.1'),'192.0.2.1')
        for bad in ['https://example.com','example.com:443','a.com/path','*.example.com',
                    'example.com\n{shell}', '192.0.2.1', 'localhost', '-a.example.com', 'evil..example.com']:
            with self.assertRaises(ValueError): n.domain(bad)
        for bad in ['tcp4-server','udp; id','',None]:
            with self.assertRaises(ValueError): n.protocol(bad)

    def test_queues_fixed_root_worker_and_rejects_overlap(self):
        result=n.queue(dict(operation='vpn-save',protocol='tcp',endpoint='vpn.example.com'))
        self.assertTrue(result['queued'])
        request=json.loads((self.root/'settings-pending.json').read_text())
        self.assertEqual(request['protocol'],'tcp')
        args=n.command.call_args.args
        self.assertEqual(args[-2:],('/usr/local/sbin/openvpn-panelctl','apply-settings'))
        self.assertNotIn('vpn.example.com',args)
        with self.assertRaises(ValueError): n.queue(dict(operation='vpn-save',protocol='udp',endpoint='192.0.2.1'))
        with self.assertRaises(ValueError): n.queue(dict(operation='vpn-save',protocol='udp',endpoint='192.0.2.1',path='/etc/shadow'))

    def test_tcp_and_udp_update_server_metadata_without_touching_pki(self):
        (self.root/'pki/key').write_text('unchanged-private-key')
        n.apply_vpn(dict(protocol='tcp',endpoint='vpn.example.com'))
        self.assertIn('proto tcp4-server\n',self.server.read_text())
        self.assertEqual(n.load_config()['endpoint'],'vpn.example.com')
        self.assertEqual(n.load_config()['protocol'],'tcp')
        self.assertEqual((self.root/'pki/key').read_text(),'unchanged-private-key')
        n.apply_vpn(dict(protocol='udp',endpoint='192.0.2.2'))
        self.assertIn('proto udp4\n',self.server.read_text())
        self.assertEqual(n.load_config()['protocol'],'udp')
        self.assertEqual(n.restart_vpn.call_count,2)

    def test_ssl_switch_only_after_certificate_verification_preserves_secret(self):
        n.queue(dict(operation='ssl-save',domain='panel.example.com',use_for_vpn=True))
        n.apply_pending()
        self.assertEqual(n.current_domain(),'panel.example.com')
        env=(self.root/'panel.env').read_text()
        self.assertIn('keep-secret',env)
        self.assertIn("'hash$with$dollars'",env)
        self.assertIn('PANEL_EXTRA_HOSTS=old.example.com',env)
        self.assertEqual(n.load_config()['endpoint'],'panel.example.com')
        self.assertIn('old.example.com, panel.example.com',self.caddy.read_text())
        self.assertEqual(json.loads((self.root/'settings-state.json').read_text())['status'],'completed')
        self.assertEqual(n.wait_tls.call_args_list[-1].kwargs,{'http':True})
        n.restart_vpn.assert_not_called()

    def test_failed_tls_rolls_back_host_endpoint_and_caddy(self):
        original={k:p.read_bytes() if p.exists() else None for k,p in n.paths().items()}
        n.queue(dict(operation='ssl-save',domain='new.example.com',use_for_vpn=True))
        n.wait_tls.side_effect=RuntimeError('certificate not issued')
        n.apply_pending()
        for key,path in n.paths().items(): self.assertEqual(path.read_bytes() if path.exists() else None,original[key])
        self.assertEqual(json.loads((self.root/'settings-state.json').read_text())['status'],'failed')
        self.assertFalse((self.root/'settings-pending.json').exists())

    def test_failed_vpn_start_rolls_back_protocol(self):
        n.queue(dict(operation='vpn-save',protocol='tcp',endpoint='vpn.example.com'))
        n.restart_vpn.side_effect=[RuntimeError('bind failed'),None]
        n.apply_pending()
        self.assertIn('proto udp4',self.server.read_text())
        self.assertEqual(n.load_config()['protocol'],'udp')
        self.assertEqual(json.loads((self.root/'settings-state.json').read_text())['error'],'apply_failed')

    def test_cli_rollback_restores_previous_settings_and_cancels_pending(self):
        n.queue(dict(operation='vpn-save',protocol='tcp',endpoint='new.example.com'))
        n.apply_pending()
        (self.root/'settings-pending.json').write_text('{}')
        n.rollback()
        self.assertEqual(n.load_config()['endpoint'],'192.0.2.1')
        self.assertEqual(n.load_config()['protocol'],'udp')
        self.assertFalse((self.root/'settings-pending.json').exists())
        self.assertEqual(json.loads((self.root/'settings-state.json').read_text())['status'],'rolled_back')

    def test_bootstrap_does_not_claim_unrelated_caddy(self):
        (self.root/'caddy-owned').unlink()
        self.caddy.write_text('other.example.com { reverse_proxy localhost:9999 }')
        n.bootstrap()
        self.assertFalse((self.root/'caddy-owned').exists())
        with self.assertRaises(ValueError): n.queue(dict(operation='ssl-save',domain='panel.example.com',use_for_vpn=True))
        self.caddy.write_text('old.example.com {\n tls internal\n reverse_proxy 127.0.0.1:8000\n}')
        n.bootstrap()
        self.assertTrue((self.root/'caddy-owned').exists())

    def test_resaving_same_domain_keeps_existing_https_alias(self):
        n.queue(dict(operation='ssl-save',domain='new.example.com',use_for_vpn=True))
        n.apply_pending()
        n.queue(dict(operation='ssl-save',domain='new.example.com',use_for_vpn=False))
        n.apply_pending()
        self.assertIn('PANEL_EXTRA_HOSTS=old.example.com',(self.root/'panel.env').read_text())
        self.assertIn('old.example.com, new.example.com',self.caddy.read_text())
        self.assertEqual(n.load_config()['endpoint'],'new.example.com')

    def test_ssh_to_domain_removes_insecure_cookie_flag_only_after_tls(self):
        (self.root/'panel.env').write_text('PANEL_HOST=localhost\nPANEL_LOCAL_HTTP=1\nPANEL_SECRET=keep\n')
        def verified(*args,**kwargs):
            if not kwargs.get('http'):
                self.assertIn('PANEL_LOCAL_HTTP=1',(self.root/'panel.env').read_text())
        n.wait_tls.side_effect=verified
        n.queue(dict(operation='ssl-save',domain='new.example.com',use_for_vpn=True))
        n.apply_pending()
        self.assertEqual(n.current_domain(),'new.example.com')
        self.assertNotIn('PANEL_LOCAL_HTTP=',(self.root/'panel.env').read_text())
        self.assertNotIn('localhost,',self.caddy.read_text())
        self.assertEqual(json.loads((self.root/'settings-state.json').read_text())['status'],'completed')

    def test_failure_code_survives_rollback_without_exposing_exception(self):
        n.queue(dict(operation='ssl-save',domain='new.example.com',use_for_vpn=True))
        n.wait_tls.side_effect=n.SettingsFailure('tls_certificate')
        with self.assertLogs(level='ERROR'):
            n.apply_pending()
        state=json.loads((self.root/'settings-state.json').read_text())
        self.assertEqual(state['diagnostic'],'tls_certificate')
        self.assertEqual(state['stage'],'certificate')
        self.assertEqual(state['error'],'apply_failed')
        self.assertEqual(n.current_domain(),'old.example.com')

    def test_verified_certificate_not_lost_on_http_timeout_or_partial_status_line(self):
        # Exercise the real probe, not wait_tls: valid chain != HTTP readiness.
        certificate={'notAfter':'Dec 31 23:59:59 2030 GMT','issuer':()}
        for packets, expected in [(TimeoutError('backend slow'),False),([b'HTTP/1.',b'1 200 OK\r\n'],True)]:
            secure=Mock()
            secure.getpeercert.return_value=certificate
            secure.recv.side_effect=packets
            context=Mock()
            context.wrap_socket.return_value.__enter__=Mock(return_value=secure)
            context.wrap_socket.return_value.__exit__=Mock(return_value=False)
            raw=Mock()
            raw.__enter__=Mock(return_value=raw)
            raw.__exit__=Mock(return_value=False)
            with patch.object(n.ssl,'create_default_context',return_value=context), patch.object(n.socket,'create_connection',return_value=raw):
                result=n.probe_tls('panel.example.com')
            self.assertTrue(result['valid'])
            self.assertEqual(result['http_ok'],expected)

    def test_caddy_validation_detail_is_root_log_only(self):
        n.queue(dict(operation='ssl-save',domain='new.example.com',use_for_vpn=True))
        n.command.side_effect=n.subprocess.CalledProcessError(1,['caddy','validate'],stderr=b'private-root-detail')
        with self.assertLogs(level='ERROR') as logs:
            n.apply_pending()
        state=json.loads((self.root/'settings-state.json').read_text())
        self.assertEqual(state['diagnostic'],'caddy_validate')
        self.assertNotIn('private-root-detail',json.dumps(state))
        self.assertIn('private-root-detail','\n'.join(logs.output))

    def test_first_caddy_start_skips_reset_for_unloaded_inactive_unit(self):
        n.subprocess.run.return_value=Mock(returncode=1)
        n.active.return_value=False
        n.caddy_apply({})
        calls=[call.args for call in n.command.call_args_list]
        self.assertNotIn(('/usr/bin/systemctl','reset-failed','caddy.service'),calls)
        self.assertIn(('/usr/bin/systemctl','start','caddy.service'),calls)

    def test_caddy_failed_unit_is_reset_before_start_limit_retry(self):
        n.subprocess.run.return_value=Mock(returncode=0)
        n.active.return_value=False
        n.caddy_apply({})
        calls=[call.args for call in n.command.call_args_list]
        self.assertLess(calls.index(('/usr/bin/systemctl','reset-failed','caddy.service')),
                        calls.index(('/usr/bin/systemctl','start','caddy.service')))
