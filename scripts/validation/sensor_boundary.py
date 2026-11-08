"""Private acceptance fixture: owned nonce endpoints; never contact real IMDS."""
from pathlib import Path
import importlib.util,ipaddress,json,os,secrets,subprocess,sys,time
BASE=Path(sys.argv[1]).resolve(); SRC=BASE/'src'; OUT=BASE/'boundary'; OUT.mkdir(exist_ok=False,mode=0o700)
sys.path.insert(0,str(SRC/'scripts'))
import install_lib as lib
spec=importlib.util.spec_from_file_location('network_fixture',SRC/'scripts/validation/network_fixture.py'); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
c=lib.load(BASE/'public.json'); n=c['sensor_network']; table=lib.table_name(c); bridge=n['bridge']; namespace='ctm1t-f102b'
peer='172.30.241.254'; prefix='198.18.241.0/24'; transit='198.19.241.0/30'; hostip='198.19.241.1'; nsip='198.19.241.2'
fb,fp,rh,rp='bff102b','bnf102b','rhf102b','rnf102b'; meta='169.254.169.254'
cmd=m.command; js=m.js
created=[]; processes=[]; ownedrules=[]; routepids=[]; evidence={'probes':[],'status':'RUNNING'}
def save():
 (OUT/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
def counters():
 result={}
 for family in ['inet','bridge']:
  for row in js('nft','-j','list','table',family,table)['nftables']:
   rule=row.get('rule',{}); comment=rule.get('comment','')
   if comment in ['cheesetrap:input','cheesetrap:forward','cheesetrap:bridge']:
    result[comment.split(':')[1]]=sum(x.get('counter',{}).get('packets',0) for x in rule['expr'])
 assert len(result)==3
 return result

def remove_controls():
 for family in ['inet','bridge']:
  rows=js('nft','-j','list','table',family,table)['nftables']
  for row in rows:
   rule=row.get('rule',{})
   if rule.get('comment','').startswith('ctm1-acceptance-control-'):
    cmd('nft','delete','rule',family,table,rule['chain'],'handle',str(rule['handle']))

def start(name,listeners,ns=False):
 path=OUT/(name+'.json');path.write_text(json.dumps({'listeners':listeners,'log':str(OUT/(name+'.jsonl'))}));path.chmod(0o600)
 args=['python3',str(SRC/'scripts/validation/network_fixture.py'),'serve',str(path)]
 if ns:args=['ip','netns','exec',namespace]+args
 log=(OUT/(name+'.log')).open('w');p=subprocess.Popen(args,stdout=log,stderr=log);log.close();processes.append(p)

def rawlogs():
 rows=[]
 for name in ['routed','host']:
  p=OUT/(name+'.jsonl')
  if p.exists():rows.extend(json.loads(l) for l in p.read_text().splitlines())
 return rows

def challenge(address,port,nonce,ns):
 code="import socket; s=socket.create_connection((%r,%d),2);s.sendall(%r);assert s.recv(1024)==%r;s.close()"%(address,port,(nonce+'-alive\n').encode(),(nonce+'-alive\n').encode())
 args=['python3','-c',code]
 if ns:args=['ip','netns','exec',namespace]+args
 cmd(*args)

try:
 lib.firewall_action('check',c,BASE/'install')
 network=lib.network(c)
 assert namespace not in cmd('ip','netns','list')
 links={x['ifname'] for x in js('ip','-j','link')};assert not links.intersection([fb,fp,rh,rp])
 for r in js('ip','-j','-4','route','show','table','all'):
  if r.get('dst','default')!='default':
   net=ipaddress.ip_network(r['dst'],strict=False)
   assert not any(net.overlaps(ipaddress.ip_network(x)) for x in [prefix,transit])
 assert peer not in [x['IPv4Address'].split('/')[0] for x in network['Containers'].values()]
 cmd('ip','netns','add',namespace);created.append('namespace')
 cmd('ip','link','add',fb,'type','veth','peer','name',fp);created.append(fb)
 cmd('ip','link','set',fp,'netns',namespace);cmd('ip','link','set',fb,'master',bridge);cmd('ip','link','set',fb,'up')
 cmd('ip','link','add',rh,'type','veth','peer','name',rp);created.append(rh)
 cmd('ip','link','set',rp,'netns',namespace);cmd('ip','addr','add',hostip+'/30','dev',rh);cmd('ip','link','set',rh,'up')
 ns=['ip','-n',namespace]
 cmd(*ns,'link','set','lo','up');cmd(*ns,'addr','add',peer+'/24','dev',fp);cmd(*ns,'link','set',fp,'up');cmd(*ns,'addr','add',nsip+'/30','dev',rp);cmd(*ns,'link','set',rp,'up')
 for address in [meta,'198.18.241.10','198.18.241.11','198.18.241.12','198.18.241.13']:cmd(*ns,'addr','add',address+'/32','dev','lo')
 cmd('ip','netns','exec',namespace,'sysctl','-q','-w','net.ipv4.ip_forward=0','net.ipv6.conf.all.disable_ipv6=1')
 cmd('ip','route','add',prefix,'via',nsip,'dev',rh)
 rules=[('INPUT',['-i',bridge,'-d',n['gateway'],'-p','tcp','--dport','49000']),('DOCKER-USER',['-i',bridge,'-o',rh,'-d',prefix,'-p','tcp','-m','multiport','--dports','15432,18081,18082,25'])]
 for hook,scope in rules:
  args=scope+['-m','comment','--comment','ctm1-f102b-nonce-control','-j','ACCEPT'];cmd('iptables','-w','5','-I',hook,'1',*args);ownedrules.append((hook,args))
 start('routed',[[a,p] for a,p in [('198.18.241.10',15432),('198.18.241.11',18081),('198.18.241.12',18082),('198.18.241.13',25),(meta,18084),(peer,18083)]],True)
 start('host',[[n['gateway'],49000]])
 targets=[('db','198.18.241.10',15432,'forward'),('api','198.18.241.11',18081,'forward'),('management',n['gateway'],49000,'input'),('metadata',meta,18084,'bridge'),('callback','198.18.241.12',18082,'forward'),('smtp','198.18.241.13',25,'forward'),('lateral',peer,18083,'bridge')]
 for _,address,port,_ in targets:
  for attempt in range(30):
   try:challenge(address,port,secrets.token_hex(24),address!=n['gateway']);break
   except Exception:
    if attempt==29:raise
    time.sleep(.1)
 controls=f'''insert rule inet {table} input iifname "{bridge}" ip daddr {n['gateway']} tcp dport 49000 counter accept comment "ctm1-acceptance-control-input"
insert rule inet {table} forward iifname "{bridge}" ip daddr {prefix} tcp dport {{ 15432, 18081, 18082, 25 }} counter accept comment "ctm1-acceptance-control-forward"
insert rule bridge {table} forward meta ibrname "{bridge}" ip daddr {{ {peer}, {meta} }} tcp dport {{ 18083, 18084 }} counter accept comment "ctm1-acceptance-control-bridge"
'''
 cmd('nft','-c','-f','-',input=controls);cmd('nft','-f','-',input=controls)
 for service in ['cowrie','web']:
  cid=cmd('docker','compose','--env-file',str(BASE/'install/compose.env'),'-f',str(SRC/'deploy/compose.yaml'),'ps','-q',service).strip();o=js('docker','inspect',cid)[0]
  assert o['Config']['Labels']['com.docker.compose.project']==c['project'];assert set(o['NetworkSettings']['Networks'])=={n['name']}
  exe='/cowrie/cowrie-env/bin/python3' if service=='cowrie' else '/opencanary/.venv/bin/python'
  ipv6=cmd('docker','exec',cid,exe,'-c',"from pathlib import Path; print(Path('/proc/sys/net/ipv6/conf/all/disable_ipv6').read_text().strip()); print(Path('/proc/sys/net/ipv6/conf/default/disable_ipv6').read_text().strip())").split();assert ipv6==['1','1'];evidence[service+'_ipv6_disabled']=True
  pid=o['State']['Pid'];netns=os.readlink(f'/proc/{pid}/ns/net');assert netns!=os.readlink('/proc/self/ns/net')
  exe='/cowrie/cowrie-env/bin/python3' if service=='cowrie' else '/opencanary/.venv/bin/python'
  cmd('nsenter','-t',str(pid),'-n','ip','route','add','prohibit',meta+'/32','metric','32760');routepids.append(pid)
  cmd('nsenter','-t',str(pid),'-n','ip','route','add',meta+'/32','via',peer,'dev','eth0','metric','1')
  m.validate_metadata_route(js('nsenter','-t',str(pid),'-n','ip','-j','route'),js('nsenter','-t',str(pid),'-n','ip','-j','route','get',meta),peer)
  credential=json.loads(cmd('docker','exec','-i',cid,exe,'-',input=(SRC/'scripts/validation/secret-audit.py').read_text()))
  assert not any(p['status']=='readable' for p in credential['paths'] if not(service=='web' and p['path']=='/run/cheesetrap'));evidence[service+'_credentials']=credential
  assert all('/secrets/' not in x['Source'] and x['Destination']!='/var/run/docker.sock' for x in o['Mounts'])
  if service=='web': assert sorted(x['Destination'] for x in o['Mounts'] if x['Destination'].startswith('/run/cheesetrap/'))==['/run/cheesetrap/cert.pem','/run/cheesetrap/key.pem']
  for name,address,port,hook in targets:
   nonce=secrets.token_hex(24);before=m.probe(cid,exe,address,port,nonce);assert before['echo']==nonce and before['netns']==netns
   assert sum(x['nonce']==nonce for x in rawlogs())==1
   evidence['probes'].append(dict(service=service,cid=cid,exe=exe,netns=netns,name=name,address=address,port=port,hook=hook,nonce=nonce,before=before));save()
 remove_controls();lib.firewall_action('check',c,BASE/'install')
 for p in evidence['probes']:
  before=counters()[p['hook']];after=m.probe(p['cid'],p['exe'],p['address'],p['port'],p['nonce']+'-blocked');count=counters()[p['hook']]
  assert not after['echo'] and after['error']=='TimeoutError' and after['netns']==p['netns'] and count>before
  assert not any(x['nonce']==p['nonce']+'-blocked' for x in rawlogs())
  challenge(p['address'],p['port'],p['nonce'],p['name']!='management')
  p.update(after=after,drop_before=before,drop_after=count,listener_alive=True);save()
 evidence['status']='PASS';evidence['guard_unchanged']=True;save();print('PASS: 14 actual-sensor nonce controls, denied flows and DROP counters; metadata isolated mock only')
finally:
 errors=[]
 def clean(name,fn):
  try:fn()
  except BaseException:errors.append(name)
 clean('controls',remove_controls)
 for pid in routepids:
  clean('metadata_route',lambda pid=pid:cmd('nsenter','-t',str(pid),'-n','ip','route','del',meta+'/32','via',peer,'dev','eth0','metric','1',check=False))
  clean('metadata_prohibit',lambda pid=pid:cmd('nsenter','-t',str(pid),'-n','ip','route','del','prohibit',meta+'/32','metric','32760',check=False))
 for hook,args in reversed(ownedrules):clean('iptables',lambda hook=hook,args=args:cmd('iptables','-w','5','-D',hook,*args))
 for p in processes:
  p.terminate()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 for interface in [rh,fb]:
  if interface in created:clean('link',lambda interface=interface:cmd('ip','link','del',interface))
 if 'namespace' in created:clean('namespace',lambda:cmd('ip','netns','del',namespace))
 clean('guard',lambda:lib.firewall_action('check',c,BASE/'install'))
 evidence['fixture_cleaned']=not errors;evidence['cleanup_errors']=errors;save()
 if errors:raise RuntimeError('boundary_cleanup_failed')
