#!/usr/bin/env python3
"""OCI ARM64 isolated F-01/02 acceptance. Run root with a prepared owned bundle.

Never changes cloud ingress, SSH, daemon settings or existing workloads. The
bundle is removed by the caller after receiving the nonsecret summary. Raw logs,
secrets and test database are transient. All subprocesses have bounded timeouts.
"""
import datetime
import hashlib
import http.cookiejar
import ipaddress
import json
import os
import inspect
import runpy
import traceback
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from bundle_path import resolve_bundle_path

BASE=resolve_bundle_path(sys.argv[1])
PUBLIC_IP=ipaddress.ip_address(sys.argv[2])
assert PUBLIC_IP.version==4 and PUBLIC_IP.is_global
assert os.geteuid()==0 and os.uname().machine=='aarch64'
SRC=BASE/'src'; OUT=BASE/'install'; PROJECT=BASE.name
sys.path.insert(0,str(SRC/'scripts'))
import install_lib as lib
REPORT={'status':'RUNNING','checks':[],'cleanup':{}}
NAMES=[]; LINKS=[]; RULES=[]; PROCESSES=[]; TAGS=[]
C=None; NET=None; COMPOSE_STARTED=False; GUARD_ATTEMPTED=False

def run(*args,data=None,timeout=90,check=True):
    r=subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout)
    if check and r.returncode:
        # Secrets/registry raw records must never be printed on failure.
        raise RuntimeError('command_failed:'+args[0]+':'+str(r.returncode))
    return r.stdout

def js(*a,**kw): return json.loads(run(*a,**kw))
def dc(*args,**kw): return run('docker','compose','--env-file',str(OUT/'compose.env'),'-f',str(SRC/'deploy/compose.yaml'),'-f',str(BASE/'runtime.json'),*args,**kw)
def cid(role): return dc('ps','-q',role).strip()
def query(sql): return run('docker','exec','-i',cid('postgres'),'psql','-U','postgres','-d','cheesetrap','-Atq','-v','ON_ERROR_STOP=1',data=sql)
def check(name,value):
    assert value,name
    REPORT['checks'].append(name)
    print('PASS '+name,flush=True)
def wait(fn,timeout=60):
    line=inspect.currentframe().f_back.f_lineno
    print('WAIT line='+str(line),flush=True)
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        try:
            if fn(): return
        except (OSError,RuntimeError,ValueError): pass
        time.sleep(.25)
    raise RuntimeError('condition_timeout_line_'+str(line))
def snapshot():
    ids=run('docker','ps','-aq').split()
    containers=js('docker','inspect',*ids) if ids else []
    return {'containers':{x['Id']:{'running':x['State']['Running'],'started':x['State']['StartedAt'],'restarts':x['RestartCount']} for x in containers},
            'networks':sorted(run('docker','network','ls','-q','--no-trunc').split()),
            'volumes':sorted(run('docker','volume','ls','-q').split()),
            'images':sorted(run('docker','images','--format','{{.Repository}}:{{.Tag}} {{.ID}}').splitlines()),
            'mangle_rules':[line for line in run('iptables-save','-t','mangle').splitlines() if line.startswith('-A')],
            'input_rules':[line for line in run('iptables-save','-t','filter').splitlines() if line.startswith('-A INPUT ')],
            'netns':sorted(run('ip','netns','list').splitlines()),
            'links':sorted(x['ifname'] for x in js('ip','-j','link')),
            'tables':sorted((r['table']['family'],r['table']['name']) for r in js('nft','-j','list','tables')['nftables'] if 'table' in r)}
def counter(comment):
    total=0
    for r in js('nft','-j','list','table','inet',lib.table_name(C))['nftables']:
        rule=r.get('rule',{})
        if rule.get('comment')==comment:
            total+=sum(e.get('counter',{}).get('packets',0) for e in rule['expr'])
    return total

def connect(ns,host,port,service='tcp'):
    code='''import socket,ssl,json
s=socket.socket(socket.AF_INET6 if ':' in HOST else socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1.5)
try:
 s.connect((HOST,PORT))
 if SERVICE=='https':
  ctx=ssl.create_default_context(cafile=CERT);s=ctx.wrap_socket(s,server_hostname='cheesetrap-decoy')
 if SERVICE in ('http','https'):
  s.sendall(b'GET /f0102-probe HTTP/1.0\\r\\nHost: decoy\\r\\nX-Forwarded-For: 203.0.113.254\\r\\n\\r\\n')
 data=s.recv(256);print(json.dumps({'ok':bool(data),'prefix':data[:12].decode(errors='replace')}))
except (OSError,ValueError) as e: print(json.dumps({'ok':False,'error':type(e).__name__}))
finally:s.close()
'''
    code='HOST='+repr(host)+';PORT='+str(port)+';SERVICE='+repr(service)+';CERT='+repr(str(OUT/'config/web/cert.pem'))+'\n'+code
    return js('ip','netns','exec',ns,'python3','-c',code)

def owned_rule(binary,hook,args):
    full=args+['-m','comment','--comment',PROJECT,'-j','ACCEPT']
    run(binary,'-w','5','-I',hook,'1',*full);RULES.append((binary,hook,full))

def api_client():
    jar=http.cookiejar.CookieJar(); client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    origin='http://127.0.0.1:8080'
    def request(path,data=None,method=None,extra=None):
        h={'Origin':origin,**(extra or {})}
        if data is not None:h['Content-Type']='application/json'
        req=urllib.request.Request(origin+path,data=json.dumps(data).encode() if data is not None else None,headers=h,method=method)
        with client.open(req,timeout=10) as r:return json.loads(r.read())
    token=request('/api/v1/auth/csrf')['csrf_token']
    password=secrets.token_urlsafe(32)
    dc('--profile','admin','run','--rm','-T','admin','admin','create',data='f0102-admin\n'+password+'\n')
    request('/api/v1/auth/login',{'username':'f0102-admin','password':password},extra={'X-CSRF-Token':token})
    token=request('/api/v1/auth/csrf')['csrf_token']
    settings=request('/api/v1/settings')
    request('/api/v1/settings',{'expected_version':settings['version'],'reply_to':'operator@example.test'},method='PATCH',extra={'X-CSRF-Token':token,'Idempotency-Key':secrets.token_hex(16)})
    return request

# Refuse existing installations before entering any destructive cleanup scope.
assert not OUT.exists()
assert not run('docker','ps','-aq','--filter','label=com.docker.compose.project='+PROJECT).strip()
assert PROJECT+'-sensor' not in run('docker','network','ls','--format','{{.Name}}').splitlines()
before=snapshot()
assert not any(n.startswith(PROJECT+'_') for n in before['volumes'])
assert not any(n==PROJECT+'-api' or n.startswith(PROJECT+'_') for n in run('docker','network','ls','--format','{{.Name}}').splitlines())
assert not {'ctm1-f102','ctma-f102'} & set(before['links'])
owned_table='ctm1_'+hashlib.sha256(PROJECT.encode()).hexdigest()[:12]
assert not any(name==owned_table and family in ('inet','bridge') for family,name in before['tables'])
def interrupted(signum,frame):
    signal.signal(signum,signal.SIG_IGN)
    raise RuntimeError('interrupted')
for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,interrupted)
REPORT['platform']={'arch':os.uname().machine,'cpus':os.cpu_count(),'docker':run('docker','version','--format','{{.Server.Version}}').strip()}
try:
    assert not OUT.exists()
    assert not any(PROJECT in x for x in before['images'])
    assert js('docker','info','--format','{{json .FirewallBackend}}')['Driver']=='iptables'
    for p in (32222,38080,38443,8080):lib.check_ports([p])
    for r in js('ip','-j','-4','route','show','table','all'):
        if r.get('dst','default')!='default':
            n=ipaddress.ip_network(r['dst'],strict=False)
            assert not any(n.overlaps(ipaddress.ip_network(x)) for x in ('172.30.241.0/24','198.19.240.0/29'))
    C=json.loads((SRC/'deploy/config.example.yaml').read_text())
    C['sensor_ports']={'ssh':32222,'http':38080,'https':38443}
    C.update(project=PROJECT,public_ip=str(PUBLIC_IP),allowed_client_cidr='198.19.240.2/32',is_test=False)
    C['sensor_network'].update(name=PROJECT+'-sensor',bridge='ctm1-f102',subnet='172.30.241.0/24',gateway='172.30.241.1',cowrie_ip='172.30.241.10',web_ip='172.30.241.11')
    (BASE/'restricted.json').write_text(json.dumps(C))
    lib.prepare(C,OUT)
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=cheesetrap-decoy','-addext','subjectAltName=DNS:cheesetrap-decoy','-keyout',str(OUT/'config/web/key.pem'),'-out',str(OUT/'config/web/cert.pem'))
    for name in ('key.pem','cert.pem'):
        p=OUT/'config/web'/name;os.chown(p,65534,65534);p.chmod(0o600 if name=='key.pem' else 0o644)
    # Reuse local engine/runtime images; mount the current release binary read
    # only. The override changes no ports, networks, secrets, guards or limits.
    runtime=js('docker','image','inspect','cheesetrap-9b49cbba:local')[0]['Id']
    webimage=js('docker','image','inspect','cheesetrap-9b49cbba-web:local')[0]['Id']
    ca=run('docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--entrypoint','cat','golang@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5','/etc/ssl/certs/ca-certificates.crt')
    (BASE/'ca-certificates.crt').write_text(ca);(BASE/'ca-certificates.crt').chmod(0o644)
    REPORT['ca_sha256']=hashlib.sha256(ca.encode()).hexdigest()
    services={role:{'image':runtime,'volumes':[str(BASE/'cheesetrap')+':/usr/local/bin/cheesetrap:ro',str(BASE/'ca-certificates.crt')+':/etc/ssl/certs/ca-certificates.crt:ro']} for role in ('api','collector','worker','migrate','admin')}
    services['web']={'image':webimage}
    (BASE/'runtime.json').write_text(json.dumps({'services':services}))
    REPORT['binary_sha256']=hashlib.sha256((BASE/'cheesetrap').read_bytes()).hexdigest()
    REPORT['images']={'runtime':runtime,'web':webimage}
    sensor_name=C['sensor_network']['name']
    run('docker','network','create','--driver','bridge','--subnet','172.30.241.0/24','--gateway','172.30.241.1','--opt','com.docker.network.bridge.name=ctm1-f102','--label','com.cheesetrap.install='+PROJECT,sensor_name)
    NET=sensor_name
    GUARD_ATTEMPTED=True
    lib.firewall_action('apply',C,OUT)
    COMPOSE_STARTED=True
    dc('up','-d','--wait','postgres',timeout=120);dc('run','--rm','migrate',timeout=120)
    dc('up','-d','api','cowrie','web',timeout=90)
    wait(lambda:urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health/ready',timeout=1).status==200)
    request=api_client()
    for i in (0,1):
        ns='ctf102-'+str(i);host='f102h'+str(i);peer='f102n'+str(i)
        assert ns not in before['netns'] and host not in before['links']
        run('ip','netns','add',ns);NAMES.append(ns)
        run('ip','link','add',host,'type','veth','peer','name',peer);LINKS.append(host)
        run('ip','link','set',peer,'netns',ns)
        run('ip','addr','add',f'198.19.240.{1+i*4}/30','dev',host);run('ip','link','set',host,'up')
        run('ip','-n',ns,'addr','add',f'198.19.240.{2+i*4}/30','dev',peer);run('ip','-n',ns,'link','set',peer,'up');run('ip','-n',ns,'link','set','lo','up')
        run('ip','-n',ns,'route','add','default','via',f'198.19.240.{1+i*4}')
        owned_rule('iptables','DOCKER-USER',['-i',host,'-o','ctm1-f102','-d','172.30.241.0/24','-p','tcp','-m','multiport','--dports','2222,8080,8443'])
    time.sleep(2)
    for service,port in C['sensor_ports'].items():
        wait(lambda:connect(NAMES[0],'198.19.240.1',port,service)['ok'],30)
        check('single_client_accepts_first_'+service,True)
        count=counter('cheesetrap:ingress4')
        check('single_client_denies_second_'+service,not connect(NAMES[1],'198.19.240.5',port,service)['ok'] and counter('cheesetrap:ingress4')>count)
    # Stop/remove only owned sensor/API containers before changing guard policy.
    dc('stop','api','cowrie','web');dc('rm','-f','api','cowrie','web')
    lib.firewall_action('remove',C,OUT)
    C['ingress_policy']='public_ipv4';(BASE/'public.json').write_text(json.dumps(C))
    lib.firewall_action('apply',C,OUT)
    dc('up','-d','api','cowrie','web')
    time.sleep(2)
    for service,port in C['sensor_ports'].items():
        for i,ns in enumerate(NAMES):
            wait(lambda:connect(ns,f'198.19.240.{1+i*4}',port,service)['ok'],30)
            check('public_accepts_source_'+str(i)+'_'+service,True)
    wait(lambda:urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health/ready',timeout=1).status==200)
    # Reachable IPv6 nonce listener proves ingress6, not mere absence of a route.
    run('ip','-6','addr','add','fd42:f102::1/64','dev',LINKS[0],'nodad')
    run('ip','-n',NAMES[0],'-6','addr','add','fd42:f102::2/64','dev','f102n0','nodad')
    owned_rule('ip6tables','INPUT',['-i',LINKS[0],'-d','fd42:f102::1','-p','tcp','-m','multiport','--dports','19090,38080'])
    listener="""import socket,selectors,os
sel=selectors.DefaultSelector()
for port in (19090,38080):
 s=socket.socket(socket.AF_INET6);s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('fd42:f102::1',port));s.listen();sel.register(s,selectors.EVENT_READ)
os.setgroups([]);os.setgid(65534);os.setuid(65534)
while True:
 for key,_ in sel.select():
  c,_=key.fileobj.accept();c.sendall(b'f0102-alive');c.close()
"""
    p=subprocess.Popen(['python3','-c',listener],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);PROCESSES.append(p)
    wait(lambda:connect(NAMES[0],'fd42:f102::1',19090)['ok'])
    table=lib.table_name(C)
    run('nft','insert','rule','inet',table,'ingress','iifname',LINKS[0],'ip6','saddr','fd42:f102::2','tcp','dport','38080','counter','accept','comment','"f0102-ipv6-control"')
    check('ipv6_prohibited_port_listener_alive',connect(NAMES[0],'fd42:f102::1',38080)['ok'])
    for item in js('nft','-j','list','table','inet',table)['nftables']:
        rule=item.get('rule',{})
        if rule.get('comment')=='f0102-ipv6-control':run('nft','delete','rule','inet',table,'ingress','handle',str(rule['handle']))
    before6=counter('cheesetrap:ingress6')
    check('ipv6_ingress_drop_with_live_control',not connect(NAMES[0],'fd42:f102::1',38080)['ok'] and counter('cheesetrap:ingress6')>before6)
    check('api_not_exposed_to_client',not connect(NAMES[0],'198.19.240.1',8080)['ok'])
    check('postgres_not_published',not js('docker','inspect',cid('postgres'))[0]['HostConfig']['PortBindings'])
    saved_argv=sys.argv
    try:
        sys.argv=[str(SRC/'scripts/validation/sensor_boundary.py'),str(BASE)]
        runpy.run_path(sys.argv[0],run_name='__main__')
    finally:sys.argv=saved_argv
    boundary=json.loads((BASE/'boundary/evidence.json').read_text())
    check('actual_sensor_14_positive_then_blocked_controls',boundary['status']=='PASS' and boundary['fixture_cleaned'] and len(boundary['probes'])==14)
    REPORT['sensor_boundary']={'probes':len(boundary['probes']),'guard_unchanged':boundary['guard_unchanged']}
    # Check host and routed API new connections, with explicit positive controls.
    api=js('docker','inspect',cid('api'))[0];pid=str(api['State']['Pid']);ab=lib.api_bridge(C)
    ag=api['NetworkSettings']['Networks'][PROJECT+'-api']['Gateway']
    nonce=secrets.token_hex(24);config=BASE/'api-control.json'
    config.write_text(json.dumps({'listeners':[[ag,49001]],'log':str(BASE/'api-control.jsonl')}))
    p=subprocess.Popen(['python3',str(SRC/'scripts/validation/network_fixture.py'),'serve',str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);PROCESSES.append(p)
    owned_rule('iptables','INPUT',['-i',ab,'-d',ag,'-p','tcp','--dport','49001'])
    # The routed fixture is another host interface: INPUT is the actual hook.
    code="import socket; s=socket.create_connection((%r,49001),1);s.sendall(%r);assert s.recv(1024)==%r"%(ag,(nonce+'\n').encode(),(nonce+'\n').encode())
    wait(lambda:bool(run('python3','-c',code+';print("alive")')))
    table=lib.table_name(C)
    run('nft','insert','rule','inet',table,'input','iifname',ab,'ip','daddr',ag,'tcp','dport','49001','counter','accept','comment','"f0102-api-control"')
    run('nsenter','-t',pid,'-n','python3','-c',code)
    for item in js('nft','-j','list','table','inet',table)['nftables']:
        rule=item.get('rule',{})
        if rule.get('comment')=='f0102-api-control':run('nft','delete','rule','inet',table,'input','handle',str(rule['handle']))
    count=counter('cheesetrap:api-input')
    r=subprocess.run(['nsenter','-t',pid,'-n','python3','-c',code],capture_output=True,timeout=5)
    check('api_host_egress_denied_with_live_control',r.returncode!=0 and counter('cheesetrap:api-input')>count)
    lib.firewall_action('check',C,OUT)
    # Verify source IPs from actual sensor logs before adding synthetic lookup
    # input. No packets are sent to the synthetic source IP or its abuse address.
    raw=[json.loads(l) for l in (OUT/'logs/web/events.jsonl').read_text().splitlines()]
    REPORT['web_raw_keys']=sorted(raw[-1])
    observed={x.get('peer_ip') for x in raw}
    check('http_original_sources_not_forwarded_header',{'198.19.240.2','198.19.240.6'}<=observed and '203.0.113.254' not in observed)
    rawssh=[json.loads(l) for l in (OUT/'logs/cowrie/cowrie.json').read_text().splitlines()]
    check('ssh_original_sources',{'198.19.240.2','198.19.240.6'}<={x.get('src_ip') for x in rawssh})
    # Stop sensor writers before fixture append; same evidence parser is used.
    dc('stop','cowrie','web')
    target='8.8.8.8'
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    with (OUT/'logs/cowrie/cowrie.json').open('a') as f:
        for i in range(10):
            f.write(json.dumps({'eventid':'cowrie.login.failed','timestamp':now,'src_ip':target,'src_port':43000+i,'dst_ip':'172.30.241.10','dst_port':2222,'session':'f0102-synthetic-'+str(i),'username':'fixture','password':'never-real'})+'\n')
    dc('up','-d','collector')
    wait(lambda:int(query("SELECT count(*) FROM cheesetrap.events WHERE source_ip='8.8.8.8';"))==10)
    dc('stop','collector')
    # Only time-window setup is synthetic, avoiding a day-long wait. Production
    # worker still seals against the continuous cursor and builds the revision.
    query("INSERT INTO cheesetrap.report_windows(start_at,end_at,settings_version) SELECT min(ingested_at)-interval '1 second',clock_timestamp(),1 FROM cheesetrap.events; UPDATE cheesetrap.reporting_schedule_cursor SET next_start=(SELECT min(start_at) FROM cheesetrap.report_windows);")
    check('registry_cache_initially_empty',int(query('SELECT count(*) FROM cheesetrap.enrichment_cache;'))==0)
    dc('--profile','worker','up','-d','worker')
    worker=js('docker','inspect',cid('worker'))[0]
    check('worker_smtp_secret_absent',not any('SMTP_SECRET' in e for e in worker['Config']['Env']) and not any(x['Destination']=='/run/secrets/smtp.json' for x in worker['Mounts']))
    check('worker_has_registry_egress',set(worker['NetworkSettings']['Networks'])=={PROJECT+'_management',PROJECT+'_worker_egress'})
    for role in ('api','collector','postgres'):
        info=js('docker','inspect',dc('ps','-aq',role).strip())[0]
        check(role+'_no_worker_egress',PROJECT+'_worker_egress' not in info['NetworkSettings']['Networks'])
    # Network-only WHOIS control in the worker namespace. Application referral
    # parsing and validation remain covered by the unchanged Go regression suite.
    whois_ip=socket.getaddrinfo('whois.ripe.net',43,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
    assert ipaddress.ip_address(whois_ip).is_global
    whois_code="import socket,hashlib,json; s=socket.create_connection(("+repr(whois_ip)+",43),5);s.settimeout(5);s.sendall(b'-b 193.0.6.139\\r\\n');data=s.recv(65536);s.close();print(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}))"
    whois=js('nsenter','-t',str(worker['State']['Pid']),'-n','python3','-c',whois_code,timeout=15)
    check('worker_whois_tcp43_reply',whois['bytes']>0)
    REPORT['whois_network_control']=whois
    wait(lambda:int(query("SELECT count(*) FROM cheesetrap.report_revisions WHERE recipient<>'';"))==1,180)
    reports=request('/api/v1/reports?source_ip=8.8.8.8')['items']
    check('authenticated_report_list',len(reports)==1)
    report=reports[0];revision=request('/api/v1/reports/'+report['report_id']+'/revisions/'+report['current_revision_id'])
    if 'revision' in revision:revision=revision['revision']
    registry=revision['registry']
    check('fresh_registry_lookup_succeeded',registry['lookup_succeeded'] and bool(registry['source_url']))
    check('contact_revision_evidence',bool(revision['recipient']) and revision['evidence_count']=='10' and bool(revision['content_digest']))
    REPORT['hold_reasons']=revision['hold_reasons']
    check('draft_reviewable_without_smtp',report['state']=='needs_review')
    check('smtp_attempts_zero',int(query('SELECT count(*) FROM cheesetrap.delivery_attempts;'))==0)
    check('delivery_schedule_zero',int(query('SELECT count(*) FROM cheesetrap.delivery_schedule;'))==0)
    wait(lambda:int(query("SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='draft_reports' AND state='completed';"))>0,60)
    check('draft_job_completed',int(query("SELECT count(*) FROM cheesetrap_river.river_job WHERE kind='draft_reports' AND state='completed';"))>0)
    REPORT['registry']={k:registry[k] for k in ('address','method','source_url','lookup_succeeded','queried_at')}
    REPORT['revision']={k:revision[k] for k in ('state','evidence_count','rule_count','content_digest')}
    REPORT['status']='PASS'
except BaseException as e:
    REPORT['status']='FAIL';REPORT['failure']=type(e).__name__+':'+str(e)
    # Preserve only structured diagnostics in the private bundle until caller
    # retrieves the summary. Never dump secret env or arbitrary raw log text.
    REPORT['trace']=traceback.format_exc()
    if COMPOSE_STARTED:
        (BASE/'diagnostic.log').write_text(dc('logs','--no-color','--tail','30',check=False))
    print('FAIL '+REPORT['failure'],flush=True)
finally:
    cleanup_errors=[]
    def clean(name,fn):
        try:fn()
        except BaseException:cleanup_errors.append(name)
    for p in PROCESSES:
        p.terminate()
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    if COMPOSE_STARTED:
        clean('compose_down',lambda:dc('--profile','*','down','-v','--remove-orphans',timeout=120))
    for binary,hook,args in reversed(RULES):clean('iptables',lambda b=binary,h=hook,a=args:run(b,'-w','5','-D',h,*a))
    for name in reversed(LINKS):clean('link',lambda n=name:run('ip','link','del',n))
    for name in reversed(NAMES):clean('namespace',lambda n=name:run('ip','netns','del',n))
    if GUARD_ATTEMPTED:clean('guard',lambda:lib.firewall_action('remove',C,OUT))
    if NET is not None:clean('network',lambda:run('docker','network','rm',NET))
    for tag in TAGS:clean('image',lambda t=tag:run('docker','image','rm',t))
    after=snapshot()
    REPORT['cleanup']={'errors':cleanup_errors,'baseline_equal':before==after,'changed_categories':[k for k in before if before[k]!=after[k]]}
    if cleanup_errors or before!=after:REPORT['status']='FAIL'
    (BASE/'result.json').write_text(json.dumps(REPORT,indent=2)+'\n')
    print('RESULT '+REPORT['status']+' cleanup='+json.dumps(REPORT['cleanup']),flush=True)
sys.exit(0 if REPORT['status']=='PASS' else 1)
