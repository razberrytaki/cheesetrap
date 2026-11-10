import configparser
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class RawRetentionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT/'scripts/raw_retention.py'
        assert path.exists(), 'raw retention implementation is missing'
        spec = importlib.util.spec_from_file_location('raw_retention', path)
        cls.lib = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.lib)

    def test_cowrie_extra_raw_outputs_are_disabled(self):
        config=configparser.ConfigParser(interpolation=None)
        config.read(ROOT/'deploy/cowrie/cowrie.cfg')
        self.assertFalse(config.getboolean('honeypot','ttylog',fallback=True))
        self.assertFalse(config.getboolean('output_textlog','enabled',fallback=True))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        (self.root/'config/collector').mkdir(parents=True)
        sources=[]
        for engine, name in [('cowrie','cowrie.json'),('web','events.jsonl')]:
            (self.root/'logs'/engine).mkdir(parents=True)
            (self.root/'logs'/engine/name).write_bytes(b'')
            sources.append({'engine':engine,'sensor_id':engine,'path':engine+'/'+name,'archive_paths':[]})
        (self.root/'config/collector/sources.json').write_text(json.dumps(sources))
        self.now=2000000000

    def put(self, path, size, age=0):
        p=self.root/'logs'/path
        with p.open('wb') as f: f.truncate(size)
        os.utime(p,(self.now-age,self.now-age))
        return p

    def apply(self, **kw):
        return self.lib.retain(self.root, now=self.now, **kw)

    def test_age_and_size_are_independent_per_sensor(self):
        old=self.put('cowrie/cowrie.json.2020-01-01',3,7*86400+1)
        first=self.put('web/events.jsonl.1',8,30)
        second=self.put('web/events.jsonl.2',8,10)
        self.apply(max_bytes=10)
        self.assertFalse(old.exists()); self.assertFalse(first.exists()); self.assertTrue(second.exists())
        receipt=json.loads((self.root/'logs/.retention-loss.json').read_text())
        self.assertEqual(receipt,{'version':1,'sensors':{'cowrie':1,'web':1}})
        self.assertEqual((self.root/'logs/.retention-loss.json').stat().st_mode & 0o777,0o644)
        sources=json.loads((self.root/'config/collector/sources.json').read_text())
        self.assertEqual(sources[1]['archive_paths'],['web/events.jsonl.2'])

    def test_configured_age_can_shorten_or_lengthen_default(self):
        old=self.put('web/events.jsonl.1',1,8*86400)
        self.apply(max_days=10)
        self.assertTrue(old.exists())
        self.apply(max_days=2)
        self.assertFalse(old.exists())

    def test_oversized_active_is_renamed_then_removed_and_new_inode_created(self):
        active=self.put('cowrie/cowrie.json',11)
        old=active.stat().st_ino
        self.apply(max_bytes=10)
        self.assertEqual(active.stat().st_size,0)
        self.assertNotEqual(active.stat().st_ino,old)
        self.assertEqual(list(active.parent.glob('cowrie.json.*')),[])
        self.assertEqual(json.loads((self.root/'logs/.retention-loss.json').read_text())['sensors']['cowrie'],1)

    def test_repeated_run_does_not_rotate_small_active_until_day(self):
        self.put('web/events.jsonl',2)
        self.apply()
        active=self.put('web/events.jsonl',3)
        inode=active.stat().st_ino
        self.now+=60; self.apply()
        self.assertEqual(active.stat().st_ino,inode)
        self.now+=86400; self.apply()
        self.assertNotEqual(active.stat().st_ino,inode)
        self.assertEqual(len(list(active.parent.glob('events.jsonl.*'))),2)

    def test_rejects_symlink_before_mutation(self):
        old=self.put('cowrie/cowrie.json.2020-01-01',1,8*86400)
        active=self.root/'logs/web/events.jsonl'
        active.unlink(); active.symlink_to(old)
        with self.assertRaises(ValueError): self.apply()
        self.assertTrue(old.exists())

    def test_archive_count_overflow_refuses_without_deleting(self):
        for n in range(1,66): self.put('web/events.jsonl.'+str(n),1)
        with self.assertRaises(ValueError): self.apply()
        self.assertEqual(len(list((self.root/'logs/web').glob('events.jsonl.*'))),65)

    def test_unrelated_files_are_preserved(self):
        other=self.put('cowrie/cowrie.log',12,8*86400)
        self.apply(max_bytes=10)
        self.assertTrue(other.exists())

    def test_dry_run_reports_work_without_touching_files(self):
        active=self.put('web/events.jsonl',11)
        inode=active.stat().st_ino
        result=self.lib.retain(self.root,now=self.now,max_bytes=10,dry_run=True)
        self.assertTrue(result['needs_work'])
        self.assertEqual(active.stat().st_ino,inode)
        self.assertFalse((self.root/'logs/.retention-loss.json').exists())
        self.apply(max_bytes=10)
        self.assertFalse(self.lib.retain(self.root,now=self.now,max_bytes=10,dry_run=True)['needs_work'])

class CommandCoordinationTest(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('retain_command',ROOT/'scripts/retain-raw-logs.py')
        self.cli=importlib.util.module_from_spec(spec); spec.loader.exec_module(self.cli)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'cd'
        self.state.mkdir()
        state = patch.object(self.cli, 'STATE', self.state)
        state.start()
        self.addCleanup(state.stop)
        self.calls=[]
        self.states=[True,False]
        self.failed=False

    def command(self,args):
        self.calls.append(args)
        if 'psql' in args: return json.dumps({'raw_days':2,'raw_bytes':'33554432'})
        if 'inspect' in args:
            running=self.states.pop(0)
            return json.dumps([{'Id':service+'-id','Config':{'Labels':{'com.docker.compose.service':service}},'State':{'Running':running and service!='web'}} for service in ['cowrie','web','collector']])
        if args[:2] == ['docker', 'ps']: return ''
        if 'ps' in args: return 'cowrie-id web-id collector-id'
        return ''

    def run_maintenance(self, preview=True, failure=False, config=None):
        def retain(root,**kwargs):
            self.assertEqual(kwargs.get('max_days'),2)
            self.assertEqual(kwargs.get('max_bytes'),33554432)
            if kwargs.get('dry_run'): return {'needs_work':preview}
            self.calls.append(['retention'])
            if failure: raise ValueError('retention failed')
            return {'needs_work':True}
        with patch.object(self.cli,'load',return_value=config or {}), patch.object(self.cli,'retain',side_effect=retain):
            return self.cli.maintain('/unused',command=self.command)

    def test_external_policy_uses_protected_source_and_override(self):
        with patch.object(self.cli,'external_source',create=True,return_value=['external-client']) as source,patch.object(self.cli,'external_sql',create=True,return_value=json.dumps({'raw_days':2,'raw_bytes':'33554432'})) as query:
            self.run_maintenance(config={'database':{'host':'db.example.invalid'}})
        source.assert_called_once_with(['docker'],Path('/unused'))
        query.assert_called_once_with(['external-client'],'SELECT cheesetrap.retention_policy()::text;')
        self.assertFalse(any('postgres' in args for args in self.calls))
        compose=next(args for args in self.calls if 'compose' in args)
        self.assertIn(str(ROOT/'deploy/compose.external-db.yaml'),compose)
        self.assertEqual(self.calls[-1],['docker','start','cowrie-id','collector-id'])

    def test_compose_only_install_without_cd_state_does_not_create_it(self):
        self.state.rmdir()
        self.run_maintenance()
        self.assertFalse(self.state.exists())
        self.assertIn(['retention'], self.calls)
        self.assertEqual(self.calls[-1], ['docker','start','cowrie-id','collector-id'])

    def test_no_work_only_reads_policy(self):
        self.run_maintenance(preview=False)
        self.assertEqual(len(self.calls),1)
        self.assertIn('psql',self.calls[0])

    def test_stop_verify_retain_then_restore_only_running(self):
        self.run_maintenance()
        self.assertEqual(self.calls[-4],['docker','stop','cowrie-id','web-id','collector-id'])
        self.assertEqual(self.calls[-3][1],'inspect')
        self.assertEqual(self.calls[-2],['retention'])
        self.assertEqual(self.calls[-1],['docker','start','cowrie-id','collector-id'])

    def test_resume_does_not_require_removed_one_shot_migration_container(self):
        original=self.command
        def without_migration(args):
            if 'compose' in args and 'start' in args:
                raise ValueError('one_shot_migration_container_not_present')
            return original(args)
        self.command=without_migration
        try:self.run_maintenance()
        except ValueError as error:self.fail('retention could not resume existing services: '+str(error))
        self.assertEqual(self.calls[-1],['docker','start','cowrie-id','collector-id'])

    def test_policy_failure_prevents_preview_and_stop(self):
        for output in ['', 'null', '{"raw_days":0,"raw_bytes":"1073741824"}', '{"raw_days":7,"raw_bytes":"1"}']:
            with patch.object(self.cli,'load'), patch.object(self.cli,'retain') as retain:
                with self.assertRaises((ValueError,TypeError,KeyError)):
                    self.cli.maintain('/unused',command=lambda args: output)
                retain.assert_not_called()

    def test_stop_failure_prevents_deletion_and_restart(self):
        self.states=[True,True]
        with self.assertRaises(ValueError): self.run_maintenance()
        self.assertNotIn(['retention'],self.calls)
        self.assertFalse(any('start' in args for args in self.calls))

    def test_successful_retry_does_not_restart_services_stopped_by_previous_failure(self):
        # The recovery runbook must explicitly start the operator-recorded set.
        self.states=[False,False]
        self.run_maintenance()
        self.assertIn(['retention'],self.calls)
        self.assertFalse(any('start' in args for args in self.calls))

    def test_retention_failure_keeps_services_stopped(self):
        with self.assertRaises(ValueError): self.run_maintenance(failure=True)
        self.assertFalse(any('start' in args for args in self.calls))

    def test_cd_collector_is_stopped_before_mutation_and_only_running_ids_resume(self):
        cd_id = 'a' * 64
        states = {'cowrie-id': True, 'web-id': False, 'collector-id': False, cd_id: True}
        calls = []
        def command(args):
            calls.append(args)
            if 'psql' in args: return json.dumps({'raw_days':2,'raw_bytes':'33554432'})
            if args[:2] == ['docker', 'ps']:
                self.assertIn('label=org.cheesetrap.cd-template=collector-id', args)
                return cd_id
            if 'ps' in args: return 'cowrie-id web-id collector-id'
            if args[1] == 'inspect':
                return json.dumps([dict(Id=i, Config=dict(Cmd=['collector'], Labels=
                    {'org.cheesetrap.cd-template': 'collector-id'} if i == cd_id else
                    {'com.docker.compose.service': i.removesuffix('-id')}), State=dict(Running=states[i])) for i in args[2:]])
            if args[1] in ('stop', 'start'):
                for i in args[2:]: states[i] = args[1] == 'start'
            return ''
        def retain(root, **options):
            if not options.get('dry_run'):
                self.assertFalse(any(states.values()), 'live CD collector during raw mutation')
            return {'needs_work':True}
        with patch.object(self.cli,'load'), patch.object(self.cli,'retain',side_effect=retain):
            self.cli.maintain('/unused',command=command)
        self.assertEqual(calls[-1], ['docker','start','cowrie-id',cd_id])
        self.assertFalse(states['collector-id'])
        self.assertFalse(states['web-id'])

    def test_cd_lock_blocks_maintenance_before_policy_or_mutation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(self.cli, 'STATE', Path(directory)):
            with (Path(directory) / 'lock').open('a+b') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    self.run_maintenance()
                self.assertEqual(self.calls, [])

    def test_mismatched_cd_owner_is_rejected_before_stop_or_raw_mutation(self):
        cd_id = 'a' * 64
        original = self.command
        def wrong_owner(args):
            if args[:2] == ['docker', 'ps']:
                return cd_id
            if args[:3] == ['docker', 'inspect', cd_id]:
                return json.dumps([dict(Id=cd_id, Config=dict(Cmd=['collector'], Labels={
                    'org.cheesetrap.cd-template': 'another-installation'}), State=dict(Running=True))])
            return original(args)
        self.command = wrong_owner
        with self.assertRaisesRegex(ValueError, 'invalid_cd_collector_identity'):
            self.run_maintenance()
        self.assertFalse(any('stop' in args or args == ['retention'] for args in self.calls))

    def test_maintenance_holds_cd_lock_until_resume_finishes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(self.cli, 'STATE', Path(directory)):
            original = self.command
            def competing_deploy(args):
                with (Path(directory) / 'lock').open('a+b') as lock:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return original(args)
            self.command = competing_deploy
            self.run_maintenance()
            with (Path(directory) / 'lock').open('a+b') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

if __name__=='__main__': unittest.main()
