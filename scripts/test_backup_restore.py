"""Boundary tests: real private files; Docker processes replaced at the boundary."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('backup_restore', Path(__file__).with_name('backup_restore.py'))
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.archive = self.root / 'archive'
        self.archive.mkdir()
        (self.archive / 'database.dump').write_bytes(b'private database fixture')
        self.manifest = dict(format=1, app_schema=14, river_schema=8, river_module='v0.49.0',
                             postgres_image=MOD.IMAGE, app_commit='7649eb8',
                             files={'database.dump': MOD.digest(self.archive / 'database.dump')})
        self.save_manifest()
        self.args = argparse.Namespace(backup=str(self.archive), target='cheesetrap-restore-'+'a'*32,
                                       output=str(self.root / 'restored'))
        self.commands = []
        self.docker = patch.object(MOD, 'docker_local', return_value=['docker', '--context', 'local'])
        self.docker.start()
        self.addCleanup(self.docker.stop)

    def save_manifest(self):
        (self.archive / 'manifest.json').write_text(json.dumps(self.manifest))

    def run_command(self, command, data=None, check=True):
        self.commands.append(command)
        if 'inspect' in command:
            return subprocess.CompletedProcess(command, 1, b'', b'')
        return subprocess.CompletedProcess(command, 0, b'', b'')

    def assert_no_create(self):
        self.assertFalse(any('create' in c for c in self.commands), self.commands)

    def external_backup(self,version=b'170011\n'):
        import install_lib
        source=self.root/'external'
        c=install_lib.load(Path(__file__).resolve().parents[1]/'deploy/config.example.yaml')
        ca=self.root/'database-ca.pem';ca.write_text('public CA fixture')
        c['database']={'host':'db.example.invalid','port':5432,'quota_gib':100,'allowed_cidr':'10.20.0.0/16','ca_file':str(ca)}
        install_lib.prepare(c,source)
        args=argparse.Namespace(external=True,container=None,database='cheesetrap',app_version='7649eb8',install_root=str(source),output=str(self.root/'backup'))
        def query(command,data=None,check=True):
            if 'network' in command and 'inspect' in command:
                return subprocess.CompletedProcess(command,0,json.dumps([{'Driver':'bridge','Labels':{'com.cheesetrap.install':c['project']},'Options':{'com.docker.network.bridge.name':install_lib.database_bridge(c)}}]).encode(),b'')
            self.commands.append(command)
            if data and b'server_version_num' in data: result=version
            elif data and b'version_id' in data: result=b'31\n'
            else: result=b'8\n'
            return subprocess.CompletedProcess(command,0,result,b'')
        def dump(command,path,output=False):
            self.commands.append(command);path.write_bytes(b'database fixture')
        with patch.object(MOD,'run',side_effect=query),patch.object(MOD,'transfer',side_effect=dump):
            try: MOD.backup(args)
            except TypeError: self.fail("external backup rejected without container source")
        return source

    def test_external_backup_keeps_credentials_off_host_argv(self):
        source=self.external_backup()
        url=(source/'secrets/migration-url').read_text().strip()
        for command in self.commands:
            self.assertNotIn(url,' '.join(command))
            self.assertNotIn(url.split(':')[2].split('@')[0],' '.join(command))
            self.assertIn('run',command)
            self.assertIn('--rm',command)
            self.assertIn(MOD.IMAGE,command)
            self.assertIn('cheesetrap-example-database',command)
            self.assertIn(str(source/'secrets/migration-url')+':/run/secrets/database-url:ro,z',command)
            self.assertIn(str(self.root/'database-ca.pem')+':/run/secrets/database-ca.pem:ro,z',command)
        self.assertTrue(any('pg_dump' in ' '.join(command) for command in self.commands))
        manifest=json.loads((self.root/'backup/manifest.json').read_text())
        self.assertEqual((manifest['app_schema'],manifest['river_schema']),(31,8))
        self.assertFalse(any('secrets' in name for name in manifest['files']))

    def test_external_backup_reads_secret_as_its_owning_app_uid(self):
        self.external_backup()
        for command in self.commands:
            self.assertEqual(command[command.index('--user')+1],'10001:10001')

    def test_external_backup_rejects_newer_server_before_dump(self):
        with self.assertRaisesRegex(ValueError,'server_newer_than_pg_dump'):
            self.external_backup(b'180001\n')
        self.assertFalse(any('pg_dump' in ' '.join(command) for command in self.commands))

    def test_supported_schema_restore_preserves_exact_review_version(self):
        for version in (14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31):
            with self.subTest(version=version):
                self.manifest['app_schema'] = version
                self.save_manifest()
                self.args.output = str(self.root / ('restored-' + str(version)))

                def successful(command, data=None, check=True):
                    response = self.run_command(command, data, check)
                    if 'port' in command:
                        return subprocess.CompletedProcess(command, 0, b'127.0.0.1:54321\n', b'')
                    return response

                def schema_query(docker, target, database, query):
                    if 'max(version_id)' in query:
                        return str(version)
                    if 'max(version)' in query:
                        return '8'
                    return ''

                with patch.object(MOD, 'run', side_effect=successful), \
                        patch.object(MOD, 'sql', side_effect=schema_query), \
                        patch.object(MOD, 'transfer'):
                    MOD.restore(self.args)
                review = json.loads((Path(self.args.output) / 'review.json').read_text())
                self.assertEqual(review['app_schema'], version)
                self.assertEqual(review['river_schema'], 8)
                self.assertEqual(review['app_commit'], self.manifest['app_commit'])
                self.assertTrue(review['delivery_disabled'])

    def test_schema24_manifest_must_match_restored_database(self):
        self.manifest['app_schema'] = 24
        self.save_manifest()
        for actual_app, actual_river in (('23', '8'), ('24', '7')):
            with self.subTest(app=actual_app, river=actual_river):
                self.args.output = str(self.root / ('mismatch-' + actual_app + '-' + actual_river))
                def schema_query(docker, target, database, query):
                    if 'max(version_id)' in query:
                        return actual_app
                    if 'max(version)' in query:
                        return actual_river
                    return ''
                with patch.object(MOD, 'run', side_effect=self.run_command), \
                        patch.object(MOD, 'sql', side_effect=schema_query), \
                        patch.object(MOD, 'transfer'):
                    with self.assertRaisesRegex(ValueError, 'snapshot_schema_version_mismatch'):
                        MOD.restore(self.args)
                self.assertFalse((Path(self.args.output) / 'review.json').exists())

    def test_unsupported_schema_rejected_before_create(self):
        for version in (13, 32, 999, '17', None):
            with self.subTest(version=version):
                self.manifest['app_schema'] = version
                self.save_manifest()
                with patch.object(MOD, 'run', side_effect=self.run_command):
                    with self.assertRaisesRegex(ValueError, 'backup_version_incompatible'):
                        MOD.restore(self.args)
                self.assert_no_create()
                self.assertFalse(Path(self.args.output).exists())

    def test_bad_checksum_rejected_before_create(self):
        (self.archive / 'database.dump').write_bytes(b'corrupted')
        with patch.object(MOD, 'run', side_effect=self.run_command):
            with self.assertRaisesRegex(ValueError, 'backup_checksum_invalid'):
                MOD.restore(self.args)
        self.assert_no_create()
        self.assertFalse(Path(self.args.output).exists())

    def test_unexpected_and_traversal_entries_rejected_before_create(self):
        for name in ('../outside', 'config/secrets/smtp.json'):
            with self.subTest(name=name):
                self.manifest['files'][name] = '0'*64
                self.save_manifest()
                with patch.object(MOD, 'run', side_effect=self.run_command):
                    with self.assertRaisesRegex(ValueError, 'backup_manifest_invalid'):
                        MOD.restore(self.args)
                self.assert_no_create()
                del self.manifest['files'][name]

    def test_existing_output_is_never_overwritten(self):
        destination = Path(self.args.output)
        destination.mkdir()
        marker = destination / 'keep'
        marker.write_bytes(b'original')
        with patch.object(MOD, 'run', side_effect=self.run_command):
            with self.assertRaises(FileExistsError):
                MOD.restore(self.args)
        self.assertEqual(marker.read_bytes(), b'original')
        self.assert_no_create()

    def test_private_config_symlink_is_rejected_before_dump(self):
        install = self.root / 'install'
        install.mkdir()
        private = self.root / 'smtp-secret'
        private.write_bytes(b'private credential')
        (install / 'install.json').symlink_to(private)
        args = argparse.Namespace(container='source-postgres', database='cheesetrap',
                                  app_version='7649eb8', install_root=str(install), output=str(self.root / 'backup'))
        with patch.object(MOD, 'transfer') as transfer:
            with self.assertRaisesRegex(ValueError, 'regular_file_required'):
                MOD.backup(args)
            transfer.assert_not_called()
        self.assertEqual(private.read_bytes(), b'private credential')

    def test_leading_option_container_rejected_before_any_docker(self):
        args = argparse.Namespace(container='--privileged', database='cheesetrap', app_version='7649eb8',
                                  install_root=str(self.root), output=str(self.root / 'backup'))
        with patch.object(MOD, 'docker_local', side_effect=AssertionError('Docker reached before rejecting option-like container')) as docker:
            with self.assertRaisesRegex(ValueError, 'invalid_source'):
                MOD.backup(args)
            docker.assert_not_called()

    def test_bootstrap_secret_is_private_and_read_only_with_container_label(self):
        def inspect_create(command, data=None, check=True):
            response = self.run_command(command, data, check)
            if 'create' in command:
                destination = Path(self.args.output)
                secret = destination / 'bootstrap-password'
                self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
                self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
                self.assertTrue(str(secret) + ':/run/secrets/password:ro,Z' in command,
                                'bootstrap secret requires a read-only private container label')
                self.assertNotIn('--privileged', command)
                self.assertNotIn('label=disable', command)
                self.assertFalse(secret.read_text() in ' '.join(command), 'credential leaked into Docker arguments')
                raise ValueError('mount_verified')
            return response

        previous_umask = MOD.os.umask(0o077)
        self.addCleanup(MOD.os.umask, previous_umask)
        with patch.object(MOD, 'run', side_effect=inspect_create):
            with self.assertRaisesRegex(ValueError, 'mount_verified'):
                MOD.restore(self.args)
        self.assertTrue(any('create' in command for command in self.commands))

    def test_readiness_waits_for_tcp_server_after_image_initialization(self):
        def inspect_probe(command, data=None, check=True):
            response = self.run_command(command, data, check)
            if 'pg_isready' in command:
                probe = command[command.index('pg_isready'):]
                self.assertEqual(probe, ['pg_isready', '-h', '127.0.0.1', '-U', 'postgres'])
                raise ValueError('probe_verified')
            return response
        with patch.object(MOD, 'run', side_effect=inspect_probe):
            with self.assertRaisesRegex(ValueError, 'probe_verified'):
                MOD.restore(self.args)

    def test_cleanup_only_removes_container_created_by_this_run(self):
        for fail_at in ('create', 'start'):
            with self.subTest(fail_at=fail_at):
                self.commands.clear()
                self.args.output = str(self.root / ('restored-'+fail_at))
                def failing(command, data=None, check=True):
                    response = self.run_command(command, data, check)
                    if fail_at in command:
                        raise ValueError('injected_failure')
                    return response
                with patch.object(MOD, 'run', side_effect=failing):
                    with self.assertRaisesRegex(ValueError, 'injected_failure'):
                        MOD.restore(self.args)
                removals = [c for c in self.commands if 'rm' in c]
                expected = [] if fail_at == 'create' else [
                    ['docker', '--context', 'local', 'rm', '-f', '-v', self.args.target]]
                self.assertEqual(removals, expected)


if __name__ == '__main__':
    unittest.main()
