#!/usr/bin/env python3
"""PostgreSQL backup and isolated local restore. Never print subprocess data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

IMAGE = 'postgres:17.11-bookworm@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826'
CONFIG = ('install.json', 'compose.env', 'config/cowrie.cfg', 'config/userdb.txt',
          'config/web/opencanary.conf', 'config/web/cert.pem', 'config/collector/sources.json')
ROLES = ('migration', 'api', 'collector', 'worker')


def run(args, data=None, check=True):
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if check and p.returncode:
        raise ValueError('subprocess_failed')
    return p


def digest(path):
    checksum = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            checksum.update(block)
    return checksum.hexdigest()


def transfer(args, path, output=False):
    # A multi-GB database must not be buffered in Python memory.
    with path.open('xb' if output else 'rb') as f:
        p = subprocess.run(args, stdin=None if output else f,
                           stdout=f if output else subprocess.DEVNULL,
                           stderr=subprocess.PIPE, timeout=120)
    if p.returncode:
        raise ValueError('database_transfer_failed')


def docker_local():
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'):
        raise ValueError('docker_target_override_refused')
    context = run(['docker', 'context', 'show']).stdout.decode().strip()
    info = json.loads(run(['docker', 'context', 'inspect', context]).stdout)
    if not info[0]['Endpoints']['docker']['Host'].startswith('unix://'):
        raise ValueError('local_docker_required')
    return ['docker', '--context', context]


def sql(docker, container, database, statement):
    return run(docker + ['exec', '-i', container, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', database], statement.encode()).stdout.decode().strip()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular_file_required')
    # Do not follow symlinks in any parent directory either.
    if any(p.is_symlink() for p in path.parents):
        raise ValueError('symlink_refused')


def external_source(docker,source):
    import install_lib
    regular(source/'install.json')
    config=install_lib.load(source/'install.json')
    if 'database' not in config: raise ValueError('external_database_configuration_required')
    url=source/'secrets/migration-url'
    ca=Path(config['database']['ca_file'])
    regular(url); regular(ca)
    if url.stat().st_mode&0o077 or url.stat().st_size>4096: raise ValueError('private_secret_file_required')
    network=config['project']+'-database'
    obj=json.loads(run(docker+['network','inspect',network]).stdout)[0]
    if obj.get('Driver')!='bridge' or obj.get('Internal') or obj.get('EnableIPv6') or obj.get('Labels',{}).get('com.cheesetrap.install')!=config['project'] or obj.get('Options',{})!={'com.docker.network.bridge.name':install_lib.database_bridge(config)}:
        raise ValueError('database_network_identity_mismatch')
    return docker+['run','--rm','-i','--user','10001:10001','--network',network,'--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true',
                   '--volume',f'{url}:/run/secrets/database-url:ro,z','--volume',f'{ca}:/run/secrets/database-ca.pem:ro,z',IMAGE]


def external_sql(command,statement):
    return run(command+['sh','-eu','-c','exec psql -X -qAt -v ON_ERROR_STOP=1 --dbname="$(cat /run/secrets/database-url)"'],statement.encode()).stdout.decode().strip()


def backup(a):
    external=getattr(a,'external',False)
    if (external and (a.container is not None or a.database!='cheesetrap')) or (not external and (not a.container or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', a.container) or not re.fullmatch(r'[a-zA-Z0-9_]+', a.database))):
        raise ValueError('invalid_source')
    if not re.fullmatch(r'[0-9a-f]{7,40}', a.app_version):
        raise ValueError('app_git_commit_required')
    docker = docker_local()
    dest = Path(a.output)
    dest.mkdir(mode=0o700)  # Exclusive: never overwrite a previous backup.
    source = Path(a.install_root).resolve()
    for name in CONFIG:
        path = source / name
        if path.exists() or path.is_symlink():
            regular(path)
            write(dest / 'config' / name, path.read_bytes())
    if external:
        command=external_source(docker,source)
        version=external_sql(command,'SHOW server_version_num;')
        if not version.isdigit(): raise ValueError('server_version_invalid')
        if int(version)//10000>int(IMAGE.split(':')[1].split('.')[0]): raise ValueError('server_newer_than_pg_dump')
        dump=command+['sh','-eu','-c','exec pg_dump --dbname="$(cat /run/secrets/database-url)" -Fc --no-owner']
        query=lambda statement: external_sql(command,statement)
    else:
        dump=docker+['exec',a.container,'pg_dump','-U','postgres','-d',a.database,'-Fc','--no-owner']
        query=lambda statement: sql(docker,a.container,a.database,statement)
    # pg_dump has a consistent DB snapshot; no roles/passwords or globals dump.
    transfer(dump, dest / 'database.dump', output=True)
    app_schema = query('SELECT max(version_id) FROM cheesetrap.goose_db_version WHERE is_applied;')
    river_schema = query('SELECT max(version) FROM cheesetrap_river.river_migration;')
    if not app_schema.isdigit() or not river_schema.isdigit():
        raise ValueError('schema_version_invalid')
    manifest = {'format': 1, 'app_commit': a.app_version, 'app_schema': int(app_schema),
                'river_module': 'v0.49.0', 'river_schema': int(river_schema),
                'postgres_image': IMAGE, 'snapshot_completed_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'files': {str(p.relative_to(dest)): digest(p)
                          for p in dest.rglob('*') if p.is_file()}}
    write(dest / 'manifest.json', json.dumps(manifest, indent=2)+'\n')
    print('backup_complete; protected archive contains private database records')


def restore(a):
    if not re.fullmatch(r'cheesetrap-restore-[0-9a-f]{16,32}', a.target):
        raise ValueError('new_isolated_target_name_required')
    docker = docker_local()
    if run(docker + ['container', 'inspect', a.target], check=False).returncode == 0:
        raise ValueError('existing_target_refused')
    source = Path(a.backup).resolve()
    regular(source / 'manifest.json')
    manifest = json.loads((source / 'manifest.json').read_text())
    if manifest['format'] != 1 or manifest['app_schema'] not in (14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31) or manifest['river_schema'] != 8 or manifest['river_module'] != 'v0.49.0' or manifest['postgres_image'] != IMAGE:
        raise ValueError('backup_version_incompatible')
    allowed = {'database.dump'} | {'config/'+p for p in CONFIG}
    if 'database.dump' not in manifest['files'] or set(manifest['files']) - allowed:
        raise ValueError('backup_manifest_invalid')
    for name, expected_digest in manifest['files'].items():
        path = source / name
        regular(path)
        if digest(path) != expected_digest:
            raise ValueError('backup_checksum_invalid')
    dest = Path(a.output).resolve()
    dest.mkdir(mode=0o700)
    write(dest / 'bootstrap-password', secrets.token_hex(32))
    created = False
    try:
        run(docker + ['create', '--name', a.target, '--label', 'cheesetrap.restore-check=true',
                      '--publish', '127.0.0.1::5432', '--env', 'POSTGRES_PASSWORD_FILE=/run/secrets/password',
                      '--volume', f'{dest}/bootstrap-password:/run/secrets/password:ro,Z', IMAGE])
        created = True
        run(docker + ['start', a.target])
        for _ in range(60):
            if run(docker + ['exec', a.target, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], check=False).returncode == 0:
                break
            time.sleep(.5)
        else:
            raise ValueError('restore_database_not_ready')
        # Credentials are freshly generated, passed over stdin only, never archived metadata.
        passwords = {role: secrets.token_hex(32) for role in ROLES}
        sql(docker, a.target, 'postgres', '\n'.join(
            f"CREATE ROLE cheesetrap_{r} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{p}';\nALTER ROLE cheesetrap_{r} SET search_path=pg_catalog,cheesetrap;" for r,p in passwords.items())+
            "\nCREATE DATABASE cheesetrap OWNER cheesetrap_migration;\nALTER DATABASE cheesetrap SET cheesetrap.delivery_disabled='true';\nREVOKE ALL ON DATABASE cheesetrap FROM PUBLIC;\nGRANT CONNECT ON DATABASE cheesetrap TO cheesetrap_api,cheesetrap_collector,cheesetrap_worker;")
        sql(docker, a.target, 'cheesetrap', 'REVOKE ALL ON SCHEMA public FROM PUBLIC;')
        transfer(docker + ['exec', '-i', a.target, 'pg_restore', '-U', 'postgres', '-d', 'cheesetrap', '--no-owner', '--role=cheesetrap_migration', '--exit-on-error', '--single-transaction'], source / 'database.dump')
        actual_app = sql(docker, a.target, 'cheesetrap', 'SELECT max(version_id) FROM cheesetrap.goose_db_version WHERE is_applied;')
        actual_river = sql(docker, a.target, 'cheesetrap', 'SELECT max(version) FROM cheesetrap_river.river_migration;')
        if actual_app != str(manifest['app_schema']) or actual_river != str(manifest['river_schema']):
            raise ValueError('snapshot_schema_version_mismatch')
        # Restore-specific classification is privileged, atomic, and never fabricates SMTP acceptance.
        sql(docker, a.target, 'cheesetrap', """
BEGIN;
SET LOCAL ROLE cheesetrap_migration;
CREATE TABLE IF NOT EXISTS cheesetrap.restore_review (report_id uuid, snapshot_state text, classification text, classified_at timestamptz);
INSERT INTO cheesetrap.restore_review
SELECT report_id,state AS snapshot_state,'post_backup_delivery_unknown'::text AS classification,clock_timestamp() AS classified_at
FROM cheesetrap.reports WHERE state NOT IN ('sent','rejected','closed_unconfirmed');
GRANT SELECT ON cheesetrap.restore_review TO cheesetrap_api,cheesetrap_worker;
ALTER TABLE cheesetrap.reports DISABLE TRIGGER preserve_report_pointer;
UPDATE cheesetrap.reports SET state=CASE WHEN state IN ('sending','unknown') THEN 'unknown' WHEN state='held' THEN 'held' ELSE 'needs_review' END,
 delivery_uncertain=true,version=version+1,active_refresh_id=NULL
 WHERE state NOT IN ('sent','rejected','closed_unconfirmed');
ALTER TABLE cheesetrap.reports ENABLE TRIGGER preserve_report_pointer;
UPDATE cheesetrap.contact_refresh_requests SET status='superseded',completed_at=clock_timestamp() WHERE status='queued';
UPDATE cheesetrap.delivery_attempts SET result='unknown',phase='recovery',classification='smtp_interrupted',finished_at=clock_timestamp() WHERE result='sending';
UPDATE cheesetrap.smtp_tests SET status='unknown',classification='smtp_interrupted',finished_at=clock_timestamp() WHERE status='sending';
UPDATE cheesetrap.approvals SET invalidated_at=clock_timestamp() WHERE invalidated_at IS NULL;
UPDATE cheesetrap.automatic_policy SET enabled=false,version=version+1,effective_at=clock_timestamp();
COMMIT;
""")
        binding = run(docker + ['port', a.target, '5432']).stdout.decode().strip()
        match = re.fullmatch(r'127\.0\.0\.1:(\d+)', binding)
        if not match:
            raise ValueError('restore_loopback_required')
        for role,password in passwords.items():
            write(dest / (role+'-url'), f'postgresql://cheesetrap_{role}:{password}@127.0.0.1:{match[1]}/cheesetrap?sslmode=disable&connect_timeout=5\n')
        for name in manifest['files']:
            if name.startswith('config/'):
                write(dest / name, (source / name).read_bytes())
        write(dest / 'review.json', json.dumps({'delivery_disabled': True, 'classification': 'post_backup_delivery_unknown', 'app_commit': manifest['app_commit'], 'app_schema': manifest['app_schema'], 'river_schema': manifest['river_schema']})+'\n')
        print('restore_check_complete; delivery_disabled; operator_review_required')
    except BaseException:
        if created:
            run(docker + ['rm', '-f', '-v', a.target], check=False)
        raise


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='action', required=True)
    b = sub.add_parser('backup')
    source=b.add_mutually_exclusive_group(required=True)
    source.add_argument('--container')
    source.add_argument('--external',action='store_true')
    b.add_argument('--database',default='cheesetrap')
    for key in ('install-root','output','app-version'):
        b.add_argument('--'+key, required=True)
    r = sub.add_parser('restore')
    for key in ('backup','target','output'):
        r.add_argument('--'+key, required=True)
    a = p.parse_args()
    try:
        (backup if a.action == 'backup' else restore)(a)
    except Exception:
        print('backup_restore_failed; inspect inputs and permissions; no private subprocess output retained', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
