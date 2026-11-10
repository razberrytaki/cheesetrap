#!/usr/bin/env python3
"""Coordinate stopped engines before raw JSONL retention. No live copytruncate."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import re
from pathlib import Path
import sys
from install_lib import ROOT, load, run
from raw_retention import retain
from backup_restore import external_source, external_sql

OWNER = 'org.cheesetrap.cd-template'
STATE = Path('/var/lib/cheesetrap-cd')


@contextmanager
def deployment_lock():
    # Legacy Compose-only installs have no CD state. Installed CD always has it.
    if not STATE.exists():
        yield
        return
    with (STATE / 'lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def maintain(root, command=run):
    with deployment_lock():
        return maintain_locked(root, command)


def maintain_locked(root, command):
    root=Path(root).absolute()
    config=load(root/'install.json')
    dc=['docker','compose','--env-file',str(root/'compose.env'),'-f',str(ROOT/'deploy/compose.yaml')]
    # Capture one DB policy before preview or stopping services. SQL validates
    # legacy defaults; read/parse failure never falls back to destructive defaults.
    if 'database' in config:
        dc+=['-f',str(ROOT/'deploy/compose.external-db.yaml')]
        policy=json.loads(external_sql(external_source(['docker'],root),'SELECT cheesetrap.retention_policy()::text;'))
    else:
        policy=json.loads(command(dc+['exec','-T','postgres','psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','cheesetrap','-Atc','SELECT cheesetrap.retention_policy()::text']))
    days=policy['raw_days']; raw=policy['raw_bytes']
    if type(days) is not int or not 1<=days<=365 or not isinstance(raw,str) or not re.fullmatch(r'[1-9][0-9]{0,12}',raw) or not 33554432<=int(raw)<=1099511627776:
        raise ValueError('invalid_raw_retention_policy')
    options={'max_days':days,'max_bytes':int(raw)}
    preview=retain(root,dry_run=True,**options)
    if not preview['needs_work']: return preview
    services=['collector','cowrie','web']
    ids=command(dc+['ps','--all','--quiet',*services]).split()
    if not ids: raise ValueError('installation_containers_required')
    before=json.loads(command(['docker','inspect',*ids]))
    # CD retains the original Compose collector as the ownership anchor. Include
    # every clone for this exact anchor, without selecting another installation.
    for original in list(before):
        if original['Config'].get('Labels',{}).get('com.docker.compose.service') != 'collector':
            continue
        owned_ids=command(['docker','ps','--all','--quiet','--no-trunc','--filter',
                           'label='+OWNER+'='+original['Id']]).split()
        if not owned_ids: continue
        if any(not re.fullmatch('[0-9a-f]{64}', i) for i in owned_ids):
            raise ValueError('invalid_cd_collector_identity')
        collectors=json.loads(command(['docker','inspect',*owned_ids]))
        if {s['Id'] for s in collectors} != set(owned_ids) or any(
                s['Config'].get('Cmd') != ['collector'] or s['Config'].get('Labels',{}).get(OWNER) != original['Id']
                for s in collectors):
            raise ValueError('invalid_cd_collector_identity')
        before.extend(collectors)
    ids=list(dict.fromkeys(s['Id'] for s in before))
    def states(): return json.loads(command(['docker','inspect',*ids]))
    running=[s['Id'] for s in before if s['State']['Running']]
    if any(s['State'].get('Restarting') or s['State'].get('Paused') for s in before):
        raise ValueError('stable_service_state_required')
    command(['docker','stop',*ids])
    if any(s['State']['Running'] or s['State'].get('Restarting') for s in states()):
        raise ValueError('engines_and_collector_must_be_stopped')
    # A failure intentionally leaves services stopped. Fix it, refresh manifest,
    # and manually start services; restarting with stale paths is unsafe.
    result=retain(root,**options)
    # Resume the exact existing containers, without Compose dependency traversal.
    # One-shot migration containers may already have been removed.
    if running: command(['docker','start',*running])
    return result


def main():
    parser=argparse.ArgumentParser(description='Stop engines/collector, apply configured per-sensor JSONL retention, refresh sources, restart previously running services.')
    parser.add_argument('--output',required=True,help='prepared installation root')
    args=parser.parse_args()
    try:
        root=Path(args.output).absolute()
        # Lock is host-owned and outside engine-writable directories.
        with (root/'.raw-retention.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            print(json.dumps(maintain(root)))
    except (OSError,ValueError,KeyError,TypeError):
        print('raw_retention_failed; services may remain stopped; inspect ownership, archive names/count, receipt and Docker state before manual restart',file=sys.stderr)
        return 1
    return 0

if __name__=='__main__': sys.exit(main())
