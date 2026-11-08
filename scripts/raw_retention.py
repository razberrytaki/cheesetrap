"""Host-only retention. Call retain only while both engines and collector are stopped.

The CLI owns that coordination. Policy applies to managed JSONL files, per sensor,
when invoked; it is not a filesystem quota. Deletion receipts are conservative
potential-loss counters, published before unlink so collector can persist gaps.
"""
import datetime
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from install_lib import refresh_sources

DAY = 86400
MAX_BYTES = 1024**3
MAX_AGE = 7*DAY
ROTATE_BYTES = 32*1024**2
FILES = {'cowrie': ('cowrie.json', 999, r'cowrie\.json\.\d{4}-\d{2}-\d{2}(?:_\d+)?'),
         'web': ('events.jsonl', 65534, r'events\.jsonl\.[1-9][0-9]*')}


def atomic_json(path, value):
    fd, name = tempfile.mkstemp(prefix='.'+path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(value, f, sort_keys=True)
            f.write('\n'); f.flush(); os.fchmod(f.fileno(), 0o644); os.fsync(f.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('regular_unlinked_log_required')
    return info


def read_json(path, default):
    if not path.exists() and not path.is_symlink(): return default
    regular(path)
    return json.loads(path.read_text())


def retain(root, *, now=None, max_bytes=MAX_BYTES, max_days=7, dry_run=False):
    if type(max_days) is not int or not 1 <= max_days <= 365 or type(max_bytes) is not int or max_bytes < 1:
        raise ValueError('invalid_raw_retention_policy')
    max_age=max_days*DAY
    root = Path(root).absolute()
    now = time.time() if now is None else now
    for path in [root, *root.parents, root/'logs', root/'config', root/'config/collector']:
        if path.is_symlink() or not path.is_dir(): raise ValueError('real_install_directories_required')
    regular(root/'config/collector/sources.json')
    sources=json.loads((root/'config/collector/sources.json').read_text())
    if len(sources)!=2 or {s['engine'] for s in sources} != set(FILES):
        raise ValueError('installation_sensor_pair_required')
    state_path=root/'logs/.raw-retention-state.json'
    state=read_json(state_path, {})
    receipt_path=root/'logs/.retention-loss.json'
    receipt=read_json(receipt_path, {'version':1,'sensors':{}})
    if receipt.get('version')!=1 or not isinstance(receipt.get('sensors'),dict) or any(type(v) is not int or not 0<=v<2**63-1 for v in receipt['sensors'].values()):
        raise ValueError('retention_receipt_invalid')
    plans=[]
    needs_work=False
    # Validate and plan every sensor before the first mutation.
    for source in sources:
        engine=source['engine']; name,uid,pattern=FILES[engine]
        folder=root/'logs'/engine
        if folder.is_symlink() or not folder.is_dir(): raise ValueError('real_log_directory_required')
        if source['path']!=engine+'/'+name: raise ValueError('unexpected_sensor_path')
        active=folder/name; info=regular(active)
        archives=[]
        for path in folder.glob(name+'.*'):
            if not re.fullmatch(pattern,path.name): raise ValueError('unexpected_archive_name')
            archives.append((path,regular(path)))
        started=state.get(engine,{}).get('started_at')
        if started is not None and (type(started) not in (int,float) or started>now):
            raise ValueError('retention_clock_or_state_invalid')
        # Initial rotation establishes a known age boundary for existing active data.
        rotate=info.st_size>0 and (started is None or now-started>=DAY or info.st_size>=ROTATE_BYTES or info.st_size>max_bytes)
        destination=None
        if rotate:
            if engine=='cowrie':
                prefix=name+'.'+datetime.datetime.fromtimestamp(now,datetime.timezone.utc).strftime('%Y-%m-%d')
                destination=folder/prefix; n=1
                while destination.exists(): destination=folder/(prefix+'_'+str(n)); n+=1
            else:
                n=max([int(p.name.rsplit('.',1)[1]) for p,_ in archives],default=0)+1
                destination=folder/(name+'.'+str(n))
            archives.append((destination,info))
        total=info.st_size+sum(i.st_size for p,i in archives if p!=destination)
        removed=[]
        for path, entry in sorted(archives,key=lambda pair:(pair[1].st_mtime,pair[0].name)):
            if entry.st_mtime<=now-max_age or total>max_bytes:
                removed.append(path); total-=entry.st_size
        if len(archives)-len(removed)>64: raise ValueError('archive_manifest_limit_requires_operator_action')
        expected=sorted(str(p.relative_to(root/'logs')) for p,_ in archives if p not in removed)
        needs_work |= bool(destination or removed or started is None or source.get('archive_paths')!=expected)
        plans.append((engine,uid,source['sensor_id'],active,destination,removed,started))
    report={'removed':{},'bytes_limit':max_bytes,'age_seconds':max_age,'needs_work':needs_work}
    if dry_run: return report
    for engine,uid,sensor,active,destination,removed,started in plans:
        if destination is not None:
            # link refuses collisions; unlink changes no bytes and engines are stopped.
            os.link(active,destination); active.unlink()
            fd=os.open(active,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
            try:
                os.fchmod(fd,0o644)
                if os.geteuid()==0: os.fchown(fd,uid,uid)
            finally: os.close(fd)
            state[engine]={'started_at':now}
        elif started is None or active.stat().st_size==0:
            state[engine]={'started_at':now}
        for path in removed:
            receipt['sensors'][sensor]=receipt['sensors'].get(sensor,0)+1
            if receipt['sensors'][sensor]>=2**63: raise ValueError('retention_counter_overflow')
            atomic_json(receipt_path,receipt)
            path.unlink()
        report['removed'][sensor]=len(removed)
    atomic_json(state_path,state)
    refresh_sources(root)
    return report
