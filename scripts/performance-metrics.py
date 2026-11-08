#!/usr/bin/env python3
"""Read-only sampler for an explicitly isolated Linux performance installation.
Never starts services, opens ingress, changes DB state or sends mail.
"""
import argparse
import datetime
import http.cookiejar
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import time
import urllib.request


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values)*fraction)-1)] if values else None


def reference_environment(e):
    return (e.get('os') == 'Ubuntu' and e.get('version') == '24.04' and e.get('architecture') == 'aarch64'
            and e.get('cpus') == 4 and 23*1024**3 <= e.get('memory_bytes',0) <= 25*1024**3
            and 46*1024**3 <= e.get('disk_bytes',0) <= 49*1024**3 and e.get('emulated') is False)


def api_window(samples, started_at, ended_at):
    parse=lambda value:datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    start,end=parse(started_at),parse(ended_at)
    rows=[r for r in samples if start <= parse(r['api_at']) <= end]
    return dict(samples=len(rows),errors=sum(r['api_error'] for r in rows),p95_milliseconds=percentile([r['api_milliseconds'] for r in rows if not r['api_error']],.95))


def capacity_projection(events, final_bytes, initial_bytes, eps, days):
    if events <= 0 or final_bytes <= initial_bytes: return None
    per_event = (final_bytes-initial_bytes)/events
    return dict(bytes_per_event=per_event, projected_bytes=math.ceil(per_event*eps*86400*days),
                events_per_second=eps, days=days, basis='linear_projection_not_retention_measurement')


def validate_runtime(config, containers, networks):
    if config.get('is_test') is not True or not re.fullmatch(r'cheesetrap-perf-[a-z0-9-]{1,24}', config.get('project','')):
        raise ValueError('isolated performance project required')
    for c in containers:
        if c['Config']['Labels']['com.docker.compose.project'] != config['project']: raise ValueError('wrong project')
        if c['Config']['Labels']['com.docker.compose.service']=='worker':
            if any(v.startswith('CHEESETRAP_SMTP_SECRET_FILE=') and v.split('=',1)[1] for v in c['Config']['Env']): raise ValueError('SMTP must be absent')
            if not c['NetworkSettings']['Networks'] or any(not networks[n]['Internal'] for n in c['NetworkSettings']['Networks']): raise ValueError('worker must have no external network')


def command(*args):
    result=subprocess.run(args, text=True, capture_output=True, timeout=20)
    if result.returncode: raise ValueError('inspection command failed')
    return result.stdout


def data(*args): return json.loads(command(*args))


def api_client(credentials):
    if credentials.stat().st_mode & 0o077: raise ValueError('admin file permissions must be 0600')
    cred=json.loads(credentials.read_text())
    origin='http://127.0.0.1:8080'
    jar=http.cookiejar.CookieJar()
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar))
    csrf=json.loads(client.open(origin+'/api/v1/auth/csrf',timeout=5).read())['csrf_token']
    req=urllib.request.Request(origin+'/api/v1/auth/login',json.dumps(cred).encode(),headers={'Content-Type':'application/json','Origin':origin,'X-CSRF-Token':csrf})
    with client.open(req,timeout=5) as response:
        if response.status!=200: raise ValueError('API authentication failed')
    return client,origin


def environment(root, native):
    release={}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k,v=line.split('=',1);release[k]=v.strip('"')
    memory=int(next(l.split()[1] for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemTotal:')))*1024
    disk=os.statvfs(root)
    return dict(os=release.get('NAME'),version=release.get('VERSION_ID'),architecture=platform.machine(),cpus=os.cpu_count(),memory_bytes=memory,disk_bytes=disk.f_blocks*disk.f_frsize,emulated=False if native else None,kernel=platform.release(),docker=command('docker','version','--format','{{.Server.Version}}').strip())


def memory_peak(container):
    # Linux cgroup v2 high-water mark since container creation, not a sample maximum.
    pid=container['State']['Pid']
    for row in Path(f'/proc/{pid}/cgroup').read_text().splitlines():
        if row.startswith('0::'):
            path=Path('/sys/fs/cgroup')/row[3:].lstrip('/')/'memory.peak'
            if path.is_file(): return int(path.read_text())
    return None


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True);p.add_argument('--install-root',type=Path,required=True)
    p.add_argument('--admin-file',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seconds',type=int,required=True);p.add_argument('--interval',type=int,default=5)
    p.add_argument('--load-report',type=Path,help='generator report available by sampler completion; scopes API latency to actual load window')
    p.add_argument('--native-arm64-confirmed',action='store_true',help='operator verified non-emulated reference hardware; never inferred from uname alone')
    a=p.parse_args()
    if platform.system()!='Linux' or not 5 <= a.seconds <= 3600 or not 1 <= a.interval <= 30: raise ValueError('Linux and bounded duration required')
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'): raise ValueError('Docker override forbidden')
    if not command('docker','context','inspect','--format','{{.Endpoints.docker.Host}}').strip().startswith('unix://'): raise ValueError('local Docker socket required')
    import install_lib
    config=install_lib.load(a.config)
    if json.loads((a.install_root/'install.json').read_text()).get('project') != config['project']: raise ValueError('installation identity mismatch')
    ids=command('docker','ps','-q','--filter','label=com.docker.compose.project='+config['project']).split()
    if not ids: raise ValueError('test installation not running')
    containers=data('docker','inspect',*ids)
    networks={n['Name']:n for n in data('docker','network','inspect',*sorted({n for c in containers for n in c['NetworkSettings']['Networks']}))}
    validate_runtime(config,containers,networks)
    by={c['Config']['Labels']['com.docker.compose.service']:c for c in containers}
    if not {'postgres','api','collector','worker','cowrie','web'} <= by.keys(): raise ValueError('complete running installation required')
    if by['api']['HostConfig']['PortBindings']!={'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'8080'}]} or by['postgres']['HostConfig']['PortBindings']: raise ValueError('API/DB publication unsafe')
    pg=by['postgres']['Id']
    def sql(q):return data('docker','exec',pg,'psql','-U','postgres','-d','cheesetrap','-Atqc',q)
    if sql('SELECT to_json(EXISTS(SELECT 1 FROM cheesetrap.events WHERE NOT is_test))'): raise ValueError('non-test event present')
    manifest=json.loads((a.install_root/'config/collector/sources.json').read_text())
    if not isinstance(manifest,list) or not manifest or any(s.get('is_test') is not True for s in manifest): raise ValueError('test-only source manifest required')
    os.umask(0o077);a.output.mkdir(parents=True,exist_ok=False)
    env=environment(a.install_root,a.native_arm64_confirmed)
    client,origin=api_client(a.admin_file)
    latencies=[];api_errors=0;samples=[];started=time.monotonic()
    query="""SELECT json_build_object('db_bytes',pg_database_size(current_database()),'ingested_seq',ingested_seq,'detected_seq',detected_seq,'queue',(SELECT coalesce(json_object_agg(state,n),'{}') FROM (SELECT state,count(*) n FROM cheesetrap_river.river_job GROUP BY state) q),'gaps',(SELECT count(*) FROM cheesetrap.ingestion_gaps),'rejections',(SELECT count(*) FROM cheesetrap.ingestion_rejections),'delivery_attempts',(SELECT count(*) FROM cheesetrap.delivery_attempts)) FROM cheesetrap.processing_cursors WHERE singleton"""
    with (a.output/'samples.jsonl').open('x') as output:
        while True:
            t=time.monotonic();row=sql(query);row['at']=datetime.datetime.now(datetime.timezone.utc).isoformat();row['elapsed_seconds']=t-started
            row['containers']=[json.loads(line) for line in command('docker','stats','--no-stream','--format','{{json .}}',*ids).splitlines()]
            row['raw_bytes']=sum(f.stat().st_size for f in (a.install_root/'logs').rglob('*') if f.is_file() and not f.is_symlink())
            tick=time.monotonic();row['api_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();row['api_error']=False
            try:
                with client.open(origin+'/api/v1/events?limit=50',timeout=5) as response:
                    body=response.read(2*1024*1024)
                    if response.status!=200 or not isinstance(json.loads(body),dict):raise ValueError('invalid list response')
                latencies.append((time.monotonic()-tick)*1000)
            except (OSError,ValueError):api_errors+=1;row['api_error']=True
            row['api_milliseconds']=(time.monotonic()-tick)*1000
            row['sample_work_seconds']=time.monotonic()-t;samples.append(row);output.write(json.dumps(row)+'\n');output.flush()
            if time.monotonic()-started>=a.seconds:break
            time.sleep(max(0,min(a.interval-row['sample_work_seconds'],a.seconds-(time.monotonic()-started))))
    start=samples[0]['ingested_seq'];end=samples[-1]['ingested_seq']
    lag=sql(f"""SELECT json_build_object('events',count(*),'collection_p95_seconds',percentile_cont(0.95) WITHIN GROUP(ORDER BY extract(epoch FROM e.ingested_at-e.observed_at)),'detection_p95_seconds',percentile_cont(0.95) WITHIN GROUP(ORDER BY extract(epoch FROM d.completed_at-e.ingested_at)),'completed',count(d.event_id)) FROM cheesetrap.events e LEFT JOIN cheesetrap.detection_completions d USING(event_id) WHERE e.ingestion_seq>{int(start)} AND e.ingestion_seq<={int(end)}""")
    peaks={s:memory_peak(c) for s,c in by.items()}
    summary=dict(schema=1,environment=env,reference_environment=reference_environment(env),images={s:c['Image'] for s,c in by.items()},duration_seconds=time.monotonic()-started,api_samples=len(latencies),api_errors=api_errors,api_p95_milliseconds=percentile(latencies,.95),lag=lag,memory_peak_bytes=peaks,first=samples[0],last=samples[-1],db_30_day_projection=capacity_projection(end-start,samples[-1]['db_bytes'],samples[0]['db_bytes'],20,30),raw_7_day_projection=capacity_projection(end-start,samples[-1]['raw_bytes'],samples[0]['raw_bytes'],20,7),status='MEASURED_ONLY_NOT_ACCEPTANCE',limitations=['Input result and raw/normalized hash reconciliation must be joined separately.','Queue recovery must use sample times after load completion.','No long-term vacuum, retention, evidence-copy or WAL projection guarantee.','Docker stats CPU/memory are sampled; cgroup memory.peak is since container creation.'])
    if a.load_report:
        load=json.loads(a.load_report.read_text())
        summary['load_window_api']=api_window(samples,load['started_at'],load['ended_at'])
        summary['load_result']=load
        summary['load_window_api_goal_met']=summary['load_window_api']['samples']>0 and summary['load_window_api']['errors']==0 and summary['load_window_api']['p95_milliseconds']<=1000
    (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print('performance samples recorded; acceptance requires workload and integrity reconciliation')

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,subprocess.TimeoutExpired):
        raise SystemExit('performance measurement failed; inspect private samples; no acceptance claimed')
