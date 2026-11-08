#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class InstallTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert (ROOT/'scripts/install_lib.py').exists(), 'installation implementation is missing'
        spec = importlib.util.spec_from_file_location('install_lib', ROOT/'scripts/install_lib.py')
        cls.lib = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.lib)

    def config(self):
        return json.loads((ROOT/'deploy/config.example.yaml').read_text())

    def test_api_origin_shared_contract(self):
        for case in json.loads((ROOT/'testdata/api-origins.json').read_text()):
            c=self.config();c['api_origin']=case['input']
            with self.subTest(origin=case['input']):
                if not case['canonical']:
                    with self.assertRaises(ValueError): self.lib.validate(c)
                else:
                    try: self.lib.validate(c)
                    except ValueError as error: self.fail('valid API origin rejected: '+str(error))
                    with tempfile.TemporaryDirectory() as tmp:
                        out=Path(tmp)/'install';self.lib.prepare(c,out)
                        self.assertIn('CHEESETRAP_API_ORIGIN='+case['canonical']+'\n',(out/'compose.env').read_text())

    def test_api_origin_default_and_invalid_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            legacy=self.config();legacy.pop('api_origin',None)
            out=Path(tmp)/'install';self.lib.prepare(legacy,out)
            self.assertIn('CHEESETRAP_API_ORIGIN=http://127.0.0.1:8080\n',(out/'compose.env').read_text())
        for value in ('',None,False,8080,[],{}):
            c=self.config();c['api_origin']=value
            with self.subTest(value=value),self.assertRaises(ValueError): self.lib.validate(c)

    def load_balancer_config(self):
        c=self.config()
        c['load_balancer']={'backend_ip':'10.20.0.10','public_ports':{'ssh':22,'http':80,'https':443},'health_check_cidrs':['10.20.0.11/32']}
        return c

    def test_load_balancer_keeps_host_ports_separate_from_public_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'install'
            try: self.lib.prepare(self.load_balancer_config(),out)
            except ValueError as error: self.fail('valid load balancer installation rejected: '+str(error))
            sources=json.loads((out/'config/collector/sources.json').read_text())
            self.assertEqual(sources[0]['endpoints'][0]['public_port'],22)
            self.assertEqual(sources[1]['endpoints'][0]['public_port'],80)
            self.assertEqual(sources[1]['endpoints'][1]['public_port'],443)
            env=(out/'compose.env').read_text()
            self.assertIn('SENSOR_BIND_IP=10.20.0.10\n',env)
            self.assertIn('SENSOR_SSH_PORT=2222\n',env)
            self.assertIn('SENSOR_HTTP_PORT=18080\n',env)
            self.assertIn('SENSOR_HTTPS_PORT=18443\n',env)

    def test_load_balancer_rejects_unsafe_endpoints_and_health_sources(self):
        for key,value in [('backend_ip','0.0.0.0'),('backend_ip','127.0.0.1'),('backend_ip','169.254.169.254'),('backend_ip','8.8.8.8'),('backend_ip','::1'),('backend_ip','172.30.91.10'),('backend_ip','10.20.0.10\nBAD=1'),('public_ports',{'ssh':22,'http':80,'https':80}),('public_ports',{'ssh':True,'http':80,'https':443}),('health_check_cidrs',['0.0.0.0/0']),('health_check_cidrs',['10.20.0.0/24']),('health_check_cidrs',['169.254.169.254/32']),('health_check_cidrs',['::1/128']),('health_check_cidrs',['10.20.0.11/32']*2),('health_check_cidrs',None)]:
            c=self.load_balancer_config();c['load_balancer'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError): self.lib.validate(c)

    def test_load_balancer_guard_restricts_backend_address_and_health_exceptions(self):
        c=self.load_balancer_config()
        policy=self.lib.firewall(c)
        self.assertIn('ip daddr != 10.20.0.10',policy)
        self.assertIn('ip saddr != { 198.51.100.20/32, 10.20.0.11/32 }',policy)
        self.assertIn('tcp dport { 2222, 18080, 18443 }',policy)
        self.assertNotIn('tcp dport { 22, 80, 443 }',policy)
        self.assertEqual(policy.count('ct direction reply'),5)
        c['is_test']=False;c['ingress_policy']='public_ipv4'
        public=self.lib.firewall(c)
        self.assertIn('ip daddr != 10.20.0.10',public)
        self.assertNotIn('ip saddr !=',public)
        self.assertIn('cheesetrap:ingress6',public)

    def test_reject_unsupported_and_conflicting_settings(self):
        self.lib.validate(self.config())
        for key, value in [('address_family','ipv6'),('management_ssh_port',2222),('public_ip','::1'),('allowed_client_cidr','198.51.100.0/24'),('minimum_free_gib',0)]:
            c = self.config(); c[key] = value
            with self.assertRaises(ValueError): self.lib.validate(c)
        c=self.config(); c['sensor_network']['web_ip']=c['sensor_network']['cowrie_ip']
        with self.assertRaises(ValueError): self.lib.validate(c)
        c=self.config(); c['sensor_network']['bridge']='eth0; flush ruleset'
        with self.assertRaises(ValueError): self.lib.validate(c)

    def test_ingress_policy_is_explicit_and_legacy_default_is_restricted(self):
        legacy=self.config(); legacy.pop('ingress_policy',None)
        explicit=copy.deepcopy(legacy); explicit['ingress_policy']='single_client'
        self.assertEqual(self.lib.firewall(legacy),self.lib.firewall(explicit))
        for is_test in (True,False):
            legacy['is_test']=is_test
            self.assertIn('ip saddr != 198.51.100.20/32',self.lib.firewall(legacy))
        for invalid in ('', 'public', None, [], {}, True):
            c=self.config(); c['ingress_policy']=invalid
            with self.subTest(policy=invalid),self.assertRaises(ValueError): self.lib.validate(c)
        c=self.config(); c['ingress_policy']='public_ipv4'
        with self.assertRaises(ValueError): self.lib.validate(c)

    def test_public_ingress_changes_only_ipv4_source_restriction(self):
        restricted=self.config(); restricted['is_test']=False
        public=copy.deepcopy(restricted); public['ingress_policy']='public_ipv4'
        expected='\n'.join(line for line in self.lib.firewall(restricted).split('\n') if 'cheesetrap:ingress4' not in line)
        self.assertEqual(self.lib.firewall(public),expected)
        self.assertIn('cheesetrap:ingress6',expected)
        self.assertEqual(expected.count('ct direction reply'),5)
        for cidr in ('0.0.0.0/0','198.51.100.0/24','::1/128'):
            c=copy.deepcopy(public); c['allowed_client_cidr']=cidr
            with self.assertRaises(ValueError): self.lib.validate(c)
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'install'; self.lib.prepare(public,out)
            sources=json.loads((out/'config/collector/sources.json').read_text())
            self.assertTrue(all(s['is_test'] is False for s in sources))
            self.assertEqual(self.lib.load(out/'install.json'),public)

    def test_prepare_creates_separate_private_secrets_and_stable_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'install'
            self.lib.prepare(self.config(),out)
            values=[]
            for role in ('migration','api','collector','worker'):
                path=out/'secrets'/f'{role}-url'
                values.append(path.read_text())
                self.assertEqual(path.stat().st_mode&0o777,0o600)
                self.assertIn('cheesetrap_'+role+':',values[-1])
            self.assertEqual(len(set(values)),4)
            sources=json.loads((out/'config/collector/sources.json').read_text())
            self.assertEqual(sources[0]['endpoints'][0]['observed_ip'],'172.30.91.10')
            self.assertEqual(sources[1]['endpoints'][1]['public_port'],18443)
            self.assertIn('API_BRIDGE=ctma-sensor\n',(out/'compose.env').read_text())
            original=(out/'config/collector/sources.json').read_bytes()
            with self.assertRaises(ValueError): self.lib.prepare(self.config(),out)
            self.assertEqual((out/'config/collector/sources.json').read_bytes(),original)
            for value in values:
                self.assertNotIn(value,(out/'compose.env').read_text())

    def test_auxiliary_web_log_rotates_without_changing_evidence(self):
        import logging
        import logging.config
        import logging.handlers
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'install'
            self.lib.prepare(self.config(),out)
            evidence=out/'logs/web/events.jsonl'
            original=b'{"event_type":"web.request","fixture":"preserve"}\n'
            evidence.write_bytes(original)
            config=json.loads((out/'config/web/opencanary.conf').read_text())
            handlers=copy.deepcopy(config['logger']['kwargs']['handlers'])
            auxiliary=out/'logs/web/opencanary.log'
            self.assertEqual(handlers['file']['filename'],'/var/tmp/opencanary.log')
            handlers['file']['filename']=str(auxiliary)
            name='cheesetrap-install-rotation-fixture'
            logging.config.dictConfig({'version':1,'disable_existing_loggers':False,
                'formatters':config['logger']['kwargs']['formatters'],
                'handlers':handlers,'loggers':{name:{'handlers':list(handlers),'level':'WARNING','propagate':False}}})
            logger=logging.getLogger(name)
            try:
                for n in range(4):
                    logger.warning('auxiliary-%d|%s',n,'x'*(3*1024**2))
                for handler in logger.handlers: handler.flush()
                self.assertEqual({p.name for p in auxiliary.parent.glob('opencanary.log*')},
                                 {'opencanary.log','opencanary.log.1'})
                self.assertLessEqual(sum(p.stat().st_size for p in auxiliary.parent.glob('opencanary.log*')),10*1024**2)
                self.assertTrue(auxiliary.read_bytes().startswith(b'auxiliary-3|'))
                self.assertTrue(auxiliary.with_name('opencanary.log.1').read_bytes().startswith(b'auxiliary-2|'))
                self.assertEqual(evidence.read_bytes(),original)
                self.assertEqual(logger.handlers[0].maxBytes,5*1024**2)
                self.assertEqual(logger.handlers[0].backupCount,1)
            finally:
                for handler in list(logger.handlers):
                    logger.removeHandler(handler); handler.close()

    def test_preflight_detects_busy_port_and_management_connection(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); listener.listen()
            with self.assertRaises(ValueError): self.lib.check_ports([listener.getsockname()[1]])
        c=self.config()
        self.lib.check_ssh(c,'100.64.0.2 50000 100.64.0.1 22')
        for connection in ('','100.64.0.2 50000 100.64.0.1 2222','not-an-ip 1 host 22'):
            with self.assertRaises(ValueError): self.lib.check_ssh(c,connection)

    def test_firewall_keeps_owned_boundaries_and_replies(self):
        policy=self.lib.firewall(self.config())
        self.assertNotIn('flush ruleset',policy)
        self.assertIn('table inet ctm1_',policy)
        self.assertIn('table bridge ctm1_',policy)
        self.assertEqual(policy.count('ct direction reply'),5)
        self.assertEqual(policy.count('iifname "ctma-sensor" counter drop'),2)
        self.assertIn('hook prerouting priority -310',policy)
        self.assertIn('198.51.100.20/32',policy)
        self.assertIn('counter drop comment "cheesetrap:bridge"',policy)

    def test_ingress_rules_only_filter_host_local_destinations(self):
        policy=self.lib.firewall(self.config())
        ingress=[line for line in policy.splitlines() if 'cheesetrap:ingress' in line]
        self.assertEqual(len(ingress),2)
        for rule in ingress: self.assertIn('fib daddr type local',rule)

    def test_prepare_permissions_survive_private_operator_umask(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            old=os.umask(0o077)
            try:
                out=Path(tmp)/'install'; self.lib.prepare(self.config(),out)
            finally: os.umask(old)
            self.assertEqual((out/'config/collector').stat().st_mode&0o777,0o755)
            for relative,uid in [('cowrie/cowrie.json',999),('web/events.jsonl',65534)]:
                with self.subTest(active_log=relative):
                    path=out/'logs'/relative
                    self.assertTrue(path.exists(),'fresh active engine log is missing')
                    self.assertEqual(path.read_bytes(),b'')
                    self.assertEqual(path.stat().st_mode&0o777,0o644)
                    if os.geteuid()==0:
                        self.assertEqual(path.stat().st_uid,uid)
                        self.assertEqual(path.stat().st_gid,uid)


    def test_network_accepts_normalized_empty_iprange_only(self):
        c=self.config(); n=c['sensor_network']
        obj={'Driver':'bridge','EnableIPv6':False,'Labels':{'com.cheesetrap.install':c['project']},'Options':{'com.docker.network.bridge.name':n['bridge']},'IPAM':{'Config':[{'Subnet':n['subnet'],'Gateway':n['gateway'],'IPRange':''}]}}
        with patch.object(self.lib,'run',return_value=json.dumps([obj])):
            self.assertEqual(self.lib.network(c),obj)
        obj['IPAM']['Config'][0]['IPRange']='172.30.91.128/25'
        with patch.object(self.lib,'run',return_value=json.dumps([obj])):
            with self.assertRaises(ValueError): self.lib.network(c)

    def test_network_rejects_direct_routing_options(self):
        c=self.config(); n=c['sensor_network']
        obj={'Driver':'bridge','EnableIPv6':False,'Labels':{'com.cheesetrap.install':c['project']},'Options':{'com.docker.network.bridge.name':n['bridge'],'com.docker.network.bridge.gateway_mode_ipv4':'routed'},'IPAM':{'Config':[{'Subnet':n['subnet'],'Gateway':n['gateway']}]}}
        with patch.object(self.lib,'run',return_value=json.dumps([obj])):
            with self.assertRaises(ValueError): self.lib.network(c)

    def test_preflight_rejects_actual_nft_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'install';c=self.config();self.lib.prepare(c,out)
            for name in ('cert.pem','key.pem'): (out/'config/web'/name).write_text('fixture')
            def run(args,data=None):
                if args[:2]==['docker','version']: return '29.1.3'
                if args[:2]==['docker','info']: return json.dumps({'FirewallBackend':{'Driver':'nftables'},'DockerRootDir':str(out)})
                return ''
            # Isolate backend validation from the CI host's real disk space.
            # Also prove low space still stops preflight before Docker inspection.
            for free_gib,reason in ((9,'insufficient_free_disk'),(20,'unsupported_actual_docker_backend')):
                with self.subTest(free_gib=free_gib), patch.object(self.lib.os,'uname',return_value=SimpleNamespace(sysname='Linux')), patch.dict(os.environ,{'SSH_CONNECTION':'100.64.0.2 50000 100.64.0.1 22'}), patch.object(self.lib,'run',side_effect=run) as commands, patch.object(self.lib,'check_ports'), patch.object(self.lib.shutil,'disk_usage',return_value=SimpleNamespace(free=free_gib*1024**3)):
                    with self.assertRaisesRegex(ValueError,'^'+reason+'$'): self.lib.check(c,out)
                    inspected=any(call.args[0][:2]==['docker','info'] for call in commands.call_args_list)
                    self.assertEqual(inspected,free_gib>=c['minimum_free_gib'])

    def test_guard_rejects_policy_change_and_active_containers(self):
        c=self.config(); c['is_test']=False; table=self.lib.table_name(c)
        tables=json.dumps({'nftables':[{'table':{'family':f,'name':table}} for f in ('inet','bridge')]})
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp)/'firewall-state.json'
            import hashlib
            state.write_text(json.dumps({'policy_sha256':hashlib.sha256(self.lib.firewall(c).encode()).hexdigest(),'tables':{}}))
            c['ingress_policy']='public_ipv4'
            with patch.object(self.lib,'network',return_value={}),patch.object(self.lib,'api_network',return_value={}),patch.object(self.lib,'run',return_value=tables):
                with self.assertRaisesRegex(ValueError,'guard_config_changed'): self.lib.firewall_action('check',c,tmp)
            for sensor,api in (({'Containers':{'live':{}}},{}),({}, {'Containers':{'live':{}}})):
                with patch.object(self.lib,'network',return_value=sensor),patch.object(self.lib,'api_network',return_value=api),patch.object(self.lib,'run',return_value='{"nftables":[]}') as run:
                    with self.assertRaisesRegex(ValueError,'stop_sensors'): self.lib.firewall_action('apply',c,tmp)
                    self.assertEqual(run.call_count,1)

    def test_guard_remove_recovers_after_bridge_removed(self):
        c=self.config(); table=self.lib.table_name(c); calls=[]
        def run(args,data=None):
            calls.append((args,data))
            if args[:3]==['docker','network','ls']: return ''
            if args[:3]==['docker','network','inspect']: raise ValueError('missing_bridge')
            if args==['nft','-j','list','tables']: return json.dumps({'nftables':[{'table':{'family':'bridge','name':table}}]})
            if args[:4]==['nft','-j','list','table']: return json.dumps({'nftables':[{'table':{'family':'bridge','name':table,'comment':'cheesetrap:'+c['project']}}]})
            return ''
        with tempfile.TemporaryDirectory() as out,patch.object(self.lib,'run',side_effect=run):
            self.assertEqual(self.lib.firewall_action('remove',c,out),'remove_ok\n')
        self.assertIn((['nft','-f','-'],'delete table bridge '+table+'\n'),calls)

    def test_guard_remove_refuses_active_api_bridge(self):
        c=self.config(); name=c['project']+'-api'
        api={'Driver':'bridge','EnableIPv6':False,'Labels':{'com.cheesetrap.install':c['project']},'Options':{'com.docker.network.bridge.name':'ctma-sensor'},'Containers':{'abc':{}}}
        def run(args,data=None):
            if args[:3]==['docker','network','ls']: return name+'\n'
            if args[:3]==['docker','network','inspect']: return json.dumps([api])
            if args==['nft','-j','list','tables']: return json.dumps({'nftables':[]})
            return ''
        with tempfile.TemporaryDirectory() as out,patch.object(self.lib,'run',side_effect=run):
            with self.assertRaises(ValueError): self.lib.firewall_action('remove',c,out)

    def test_api_bridge_collision_blocks_preflight_and_apply(self):
        c=self.config(); collision=Path('/sys/class/net')/self.lib.api_bridge(c)
        exists=Path.exists
        calls=[]
        def has_path(path): return path==collision or exists(path)
        def run(args,data=None):
            calls.append(args)
            if args[:2]==['docker','version']: return '29.1.3'
            if args[:2]==['docker','info']: return json.dumps({'FirewallBackend':{'Driver':'iptables'},'DockerRootDir':str(out)})
            if args==['nft','-j','list','tables']: return json.dumps({'nftables':[]})
            return ''
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'install';self.lib.prepare(c,out)
            for name in ('cert.pem','key.pem'): (out/'config/web'/name).write_text('fixture')
            with patch.object(Path,'exists',has_path),patch.object(self.lib,'run',side_effect=run),patch.object(self.lib,'network',return_value={}),patch.object(self.lib,'check_ports'),patch.object(self.lib.os,'uname',return_value=SimpleNamespace(sysname='Linux')),patch.dict(os.environ,{'SSH_CONNECTION':'100.64.0.2 50000 100.64.0.1 22'}):
                for name,action in [('preflight',lambda:self.lib.check(c,out)),('apply',lambda:self.lib.firewall_action('apply',c,out))]:
                    with self.subTest(action=name):
                        with self.assertRaisesRegex(ValueError,'api_bridge_name_collision'): action()
            self.assertFalse(any(args[0]=='nft' and '-f' in args for args in calls))

    def test_manifest_refresh_is_explicit_bounded_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'install'; self.lib.prepare(self.config(),out)
            before=json.loads((out/'config/collector/sources.json').read_text())
            (out/'logs/cowrie/cowrie.json.2026-10-19').write_text('evidence\n')
            self.lib.refresh_sources(out)
            after=json.loads((out/'config/collector/sources.json').read_text())
            self.assertEqual(after[0]['sensor_id'],before[0]['sensor_id'])
            self.assertIn('cowrie/cowrie.json.2026-10-19',after[0]['archive_paths'])
            for n in range(65): (out/f'logs/cowrie/cowrie.json.2026-{n:02d}-01').touch()
            with self.assertRaises(ValueError): self.lib.refresh_sources(out)
            self.assertEqual(json.loads((out/'config/collector/sources.json').read_text()),after)

if __name__=='__main__': unittest.main()
