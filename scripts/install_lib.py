"""Single-host installation helpers. Config is the JSON subset of YAML 1.2.

Only operator-owned configuration is read here. Errors deliberately omit secret
values and subprocess output. No helper edits SSH, Docker daemon or host routes.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import uuid
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def canonical_api_origin(value):
    """Same public contract as internal/config; shared cases live in testdata."""
    try:
        if not isinstance(value,str) or not value or not value.isascii(): raise ValueError()
        u=urlsplit(value)
        if u.scheme not in ('http','https') or u.username is not None or u.password is not None or u.path or u.query or u.fragment: raise ValueError()
        host=u.hostname
        if not host or '%' in host: raise ValueError()
        try: address=ipaddress.ip_address(host)
        except ValueError: address=None
        if address is not None:
            if address.is_unspecified or address.is_multicast or (address.version==6 and address.ipv4_mapped is not None) or (u.scheme=='http' and not address.is_loopback): raise ValueError()
            host='['+str(address)+']' if address.version==6 else str(address)
        else:
            labels=host.split('.')
            if u.scheme!='https' or len(host)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels): raise ValueError()
            if re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)',labels[-1]): raise ValueError()
        canonical=u.scheme+'://'+host
        port=u.port
        if port is not None:
            if not 1<=port<=65535 or value!=canonical+':'+str(port): raise ValueError()
            if (u.scheme,port) not in (('http',80),('https',443)): canonical+=':'+str(port)
        elif value!=canonical: raise ValueError()
        return canonical
    except (ValueError,TypeError):
        raise ValueError('api_origin_invalid') from None


def validate(c):
    required = {'project','address_family','public_ip','allowed_client_cidr','management_ssh_port','sensor_ports','sensor_network','minimum_free_gib','is_test'}
    if set(c) - {'ingress_policy','load_balancer','api_origin'} != required or c['address_family'] != 'ipv4' or type(c['is_test']) is not bool:
        raise ValueError('required_settings_or_address_family_invalid')
    canonical_api_origin(c.get('api_origin','http://127.0.0.1:8080'))
    policy=c.get('ingress_policy','single_client')
    if policy not in ('single_client','public_ipv4') or (policy=='public_ipv4' and c['is_test']):
        raise ValueError('ingress_policy_invalid_or_public_test_forbidden')
    if not re.fullmatch(r'cheesetrap-[a-z0-9][a-z0-9-]{0,36}',c['project']):
        raise ValueError('project_invalid')
    public = ipaddress.ip_address(c['public_ip'])
    client = ipaddress.ip_network(c['allowed_client_cidr'])
    if public.version != 4 or public.is_unspecified or public.is_loopback or public.is_multicast or client.version != 4 or client.prefixlen != 32:
        raise ValueError('public_ipv4_and_client_32_required')
    ports = c['sensor_ports']
    if set(ports) != {'ssh','http','https'} or any(type(p) is not int or p<1 or p>65535 for p in [*ports.values(),c['management_ssh_port']]):
        raise ValueError('port_invalid')
    if len(set([*ports.values(),c['management_ssh_port'],8080])) != 5:
        raise ValueError('management_and_sensor_ports_conflict')
    if type(c['minimum_free_gib']) is not int or not 1 <= c['minimum_free_gib'] <= 100000:
        raise ValueError('disk_minimum_invalid')
    n = c['sensor_network']
    if set(n) != {'name','bridge','subnet','gateway','cowrie_ip','web_ip'} or not re.fullmatch(r'cheesetrap-[a-z0-9-]{1,50}', n['name']) or not re.fullmatch(r'ctm1-[a-z0-9-]{1,10}',n['bridge']):
        raise ValueError('sensor_network_invalid')
    subnet = ipaddress.ip_network(n['subnet'])
    addresses = [ipaddress.ip_address(n[k]) for k in ('gateway','cowrie_ip','web_ip')]
    if subnet.version != 4 or not subnet.is_private or not 24 <= subnet.prefixlen <= 28 or len(set(addresses)) != 3 or any(a not in subnet or a in (subnet.network_address,subnet.broadcast_address) for a in addresses):
        raise ValueError('sensor_addresses_invalid')
    if 'load_balancer' in c:
        validate_load_balancer(c['load_balancer'],subnet)
    return c


def validate_load_balancer(lb,sensor_subnet):
    if not isinstance(lb,dict) or set(lb)!={'backend_ip','public_ports','health_check_cidrs'}:
        raise ValueError('load_balancer_settings_invalid')
    try:
        if not isinstance(lb['backend_ip'],str): raise ValueError()
        backend=ipaddress.ip_address(lb['backend_ip'])
        private_ranges=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
        if backend.version!=4 or not any(backend in n for n in private_ranges) or backend in sensor_subnet:
            raise ValueError()
        ports=lb['public_ports']
        if not isinstance(ports,dict) or set(ports)!={'ssh','http','https'} or any(type(p) is not int or not 1<=p<=65535 for p in ports.values()) or len(set(ports.values()))!=3:
            raise ValueError()
        cidrs=lb['health_check_cidrs']
        if not isinstance(cidrs,list) or len(cidrs)>8 or any(not isinstance(s,str) for s in cidrs): raise ValueError()
        networks=[ipaddress.ip_network(s) for s in cidrs]
        if len(set(networks))!=len(networks) or any(n.version!=4 or n.prefixlen!=32 or n.network_address.is_unspecified or n.network_address.is_loopback or n.network_address.is_link_local or n.network_address.is_multicast or n.network_address.is_reserved for n in networks):
            raise ValueError()
    except (TypeError,ValueError):
        raise ValueError('load_balancer_endpoint_or_health_source_invalid') from None


def load(path):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError('duplicate_config_key')
            result[key]=value
        return result
    try:
        return validate(json.loads(Path(path).read_text(),object_pairs_hook=unique))
    except (KeyError,TypeError,OSError,json.JSONDecodeError):
        raise ValueError('configuration_invalid') from None


def write(path, data, mode=0o600, uid=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as f: f.write(data)
    path.chmod(mode)
    if uid is not None and os.geteuid()==0: os.chown(path,uid,uid)


def prepare(c, out):
    validate(c)
    out=Path(out).absolute()
    if out.exists(): raise ValueError('output_exists_refusing_identity_or_password_replacement')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(out)) or '..' in out.parts:
        raise ValueError('output_path_invalid')
    out.mkdir(mode=0o700,parents=True)
    for d in ('secrets','bootstrap','config','config/web','config/collector','logs','logs/cowrie','logs/web','state','state/cowrie','state/cowrie/lib/cowrie/tty','state/cowrie/lib/cowrie/downloads','state/cowrie/lib/cowrie/snapshots','state/cowrie/run'):
        (out/d).mkdir(parents=True,exist_ok=True)
        (out/d).chmod(0o755 if d.startswith(('logs','state','config')) else 0o700)
    if os.geteuid()==0:
        for path in (out/'state/cowrie').rglob('*'): os.chown(path,999,999)
        os.chown(out/'state/cowrie',999,999)
        os.chown(out/'logs/cowrie',999,999)
        os.chown(out/'logs/web',65534,65534)
    # Empty active files distinguish a fresh, quiet engine from missing evidence.
    # prepare refuses an existing output, and write uses exclusive creation.
    write(out/'logs/cowrie/cowrie.json','',0o644,uid=999)
    write(out/'logs/web/events.jsonl','',0o644,uid=65534)
    passwords={role:secrets.token_hex(32) for role in ('migration','api','collector','worker')}
    for role,password in passwords.items():
        write(out/'secrets'/f'{role}-url',f'postgresql://cheesetrap_{role}:{password}@postgres:5432/cheesetrap?sslmode=disable&connect_timeout=5\n',uid=10001)
    write(out/'secrets/bootstrap-password',secrets.token_hex(32)+'\n',uid=999)
    sql=[]
    for role,password in passwords.items():
        sql.append(f"CREATE ROLE cheesetrap_{role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}';")
    roles=', '.join('cheesetrap_'+role for role in passwords)
    sql += ['REVOKE ALL ON DATABASE cheesetrap FROM PUBLIC;','REVOKE ALL ON SCHEMA public FROM PUBLIC;',f'GRANT CONNECT ON DATABASE cheesetrap TO {roles};','CREATE SCHEMA cheesetrap AUTHORIZATION cheesetrap_migration;','CREATE SCHEMA cheesetrap_river AUTHORIZATION cheesetrap_migration;','REVOKE ALL ON SCHEMA cheesetrap_river FROM PUBLIC;','REVOKE ALL ON SCHEMA cheesetrap FROM PUBLIC;','GRANT USAGE ON SCHEMA cheesetrap TO cheesetrap_api,cheesetrap_collector,cheesetrap_worker;']
    sql += [f'ALTER ROLE cheesetrap_{role} SET search_path = pg_catalog, cheesetrap;' for role in passwords]
    write(out/'bootstrap/10-roles.sql','\n'.join(sql)+'\n',uid=999)
    sources=[]
    n=c['sensor_network']
    public_ports=c.get('load_balancer',{}).get('public_ports',c['sensor_ports'])
    for engine,path,services in [('cowrie','cowrie/cowrie.json',[('ssh',2222)]),('web','web/events.jsonl',[('http',8080),('https',8443)])]:
        sources.append({'sensor_id':str(uuid.uuid4()),'name':c['project']+'-'+engine,'engine':engine,'path':path,'archive_paths':[], 'is_test':c['is_test'], 'endpoints':[{'service':service,'observed_ip':n[engine+'_ip'],'observed_port':port,'public_ip':c['public_ip'],'public_port':public_ports[service]} for service,port in services]})
    write(out/'config/collector/sources.json',json.dumps(sources,indent=2)+'\n',0o644)
    cfg=(ROOT/'deploy/cowrie/cowrie.cfg').read_text().replace('PUBLIC_IPV4',c['public_ip'])
    write(out/'config/cowrie.cfg',cfg,0o644)
    for source,destination in [('deploy/cowrie/userdb.txt','config/userdb.txt'),('deploy/web/opencanary.conf','config/web/opencanary.conf')]:
        write(out/destination,(ROOT/source).read_text(),0o644)
    env={'COMPOSE_PROJECT_NAME':c['project'],'INSTALL_ROOT':str(out),'SENSOR_NETWORK':n['name'],'SENSOR_BRIDGE':n['bridge'],'API_BRIDGE':api_bridge(c),'SENSOR_SUBNET':n['subnet'],'SENSOR_GATEWAY':n['gateway'],'COWRIE_IP':n['cowrie_ip'],'WEB_IP':n['web_ip']}
    env.update({'SENSOR_'+service.upper()+'_PORT':str(port) for service,port in c['sensor_ports'].items()})
    env['CHEESETRAP_API_ORIGIN']=canonical_api_origin(c.get('api_origin','http://127.0.0.1:8080'))
    if 'load_balancer' in c: env['SENSOR_BIND_IP']=c['load_balancer']['backend_ip']
    write(out/'compose.env',''.join(k+'='+v+'\n' for k,v in env.items()))
    write(out/'install.json',json.dumps(c,indent=2)+'\n')


def refresh_sources(out):
    out=Path(out)
    path=out/'config/collector/sources.json'
    sources=json.loads(path.read_text())
    for source in sources:
        if source['engine']=='cowrie':
            candidates=sorted((out/'logs/cowrie').glob('cowrie.json.*'))
            if any(not re.fullmatch(r'cowrie\.json\.\d{4}-\d{2}-\d{2}(?:_\d+)?',p.name) for p in candidates):
                raise ValueError('cowrie_archive_name_invalid')
        else:
            candidates=sorted((out/'logs/web').glob('events.jsonl.*'))
            if any(not re.fullmatch(r'events\.jsonl\.[1-9][0-9]*',p.name) for p in candidates):
                raise ValueError('web_archive_name_invalid')
        if len(candidates)>64 or any(p.is_symlink() or not p.is_file() for p in candidates):
            raise ValueError('archive_limit_or_type_invalid_operator_action_required')
        source['archive_paths']=[str(p.relative_to(out/'logs')) for p in candidates]
    # Replace the file through the directory mount; never mutate a mounted inode.
    temp=path.with_suffix('.tmp')
    with temp.open('x') as f: f.write(json.dumps(sources,indent=2)+'\n')
    temp.chmod(0o644)
    temp.replace(path)


def check_ports(ports,bind_ip='0.0.0.0'):
    held=[]
    try:
        for port in ports:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); held.append(s)
            try: s.bind((bind_ip,port))
            except OSError: raise ValueError('required_port_unavailable') from None
    finally:
        for s in held: s.close()


def check_ssh(c, connection):
    try:
        client,client_port,server,server_port=connection.split()
        ipaddress.ip_address(client); ipaddress.ip_address(server)
        if not 0<int(client_port)<65536 or int(server_port)!=c['management_ssh_port']: raise ValueError()
    except ValueError: raise ValueError('current_management_ssh_connection_required') from None


def run(args, data=None):
    result=subprocess.run(args,input=data,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode: raise ValueError('host_command_failed_'+args[0])
    return result.stdout


def check(c,out):
    validate(c)
    if os.uname().sysname!='Linux': raise ValueError('linux_installation_required')
    check_ssh(c,os.environ.get('SSH_CONNECTION',''))
    if load(Path(out)/'install.json')!=c: raise ValueError('prepared_configuration_mismatch')
    api_network(c)
    if shutil.disk_usage(out).free < c['minimum_free_gib']*1024**3: raise ValueError('insufficient_free_disk')
    if 'load_balancer' in c:
        check_ports([8080])
        check_ports(c['sensor_ports'].values(),c['load_balancer']['backend_ip'])
    else:
        check_ports([8080,*c['sensor_ports'].values()])
    version=run(['docker','version','--format','{{.Server.Version}}']).strip()
    if not re.match(r'^[0-9]+\.',version) or int(version.split('.')[0])<28: raise ValueError('docker_28_or_newer_required')
    run(['docker','compose','version','--short'])
    info=json.loads(run(['docker','info','--format','{{json .}}']))
    if info.get('FirewallBackend',{}).get('Driver')!='iptables': raise ValueError('unsupported_actual_docker_backend')
    if shutil.disk_usage(info['DockerRootDir']).free < c['minimum_free_gib']*1024**3: raise ValueError('insufficient_docker_free_disk')
    daemon=Path('/etc/docker/daemon.json')
    settings=json.loads(daemon.read_text()) if daemon.exists() else {}
    if settings.get('firewall-backend','iptables')!='iptables' or settings.get('allow-direct-routing',False) or settings.get('iptables',True) is not True or settings.get('ip6tables',True) is not True:
        raise ValueError('unsupported_docker_network_policy')
    # Also reject command-line overrides, including an alternate daemon file.
    for proc in Path('/proc').glob('[0-9]*/cmdline'):
        try: args=proc.read_bytes().replace(b'\0',b' ').decode()
        except (OSError,UnicodeDecodeError): continue
        if Path(args.split(' ')[0]).name=='dockerd' and any(key in args for key in ('--allow-direct-routing','--firewall-backend','--iptables=false','--ip6tables=false','--config-file')):
            raise ValueError('unsupported_docker_daemon_override')
    run(['iptables','-S','DOCKER-USER'])
    run(['nft','--version'])
    for filename in ('api-url','collector-url','migration-url','worker-url','bootstrap-password'):
        p=Path(out)/'secrets'/filename
        if p.is_symlink() or not p.is_file() or p.stat().st_mode&0o077 or p.stat().st_size>4096: raise ValueError('private_secret_file_required')
    for filename in ('cert.pem','key.pem'):
        p=Path(out)/'config/web'/filename
        if p.is_symlink() or not p.is_file(): raise ValueError('web_tls_files_required')
    # Validate the exact rendered Compose too; do not print credentials/config.
    run(['docker','compose','--env-file',str(Path(out)/'compose.env'),'-f',str(ROOT/'deploy/compose.yaml'),'config','--quiet'])


def api_bridge(c): return c['sensor_network']['bridge'].replace('ctm1-','ctma-',1)


def table_name(c): return 'ctm1_'+hashlib.sha256(c['project'].encode()).hexdigest()[:12]


def firewall(c):
    validate(c)
    table=table_name(c); bridge=c['sensor_network']['bridge']; management=api_bridge(c); ports=', '.join(str(v) for v in c['sensor_ports'].values()); client=c['allowed_client_cidr']; owner='cheesetrap:'+c['project']
    ingress4='' if c.get('ingress_policy','single_client')=='public_ipv4' else f'''  iifname != "{bridge}" ip saddr != {client} fib daddr type local tcp dport {{ {ports} }} counter drop comment "cheesetrap:ingress4"\n'''
    if 'load_balancer' in c:
        lb=c['load_balancer']; backend=lb['backend_ip']
        # A preserved client IP cannot distinguish NLB traffic from direct access
        # to the host's primary public IP. Match the dedicated private destination.
        ingress4=f'''  meta nfproto ipv4 fib daddr type local ip daddr != {backend} tcp dport {{ {ports} }} counter drop comment "cheesetrap:backend-address"\n'''
        if c.get('ingress_policy','single_client')=='single_client':
            allowed=', '.join(dict.fromkeys([client,*lb['health_check_cidrs']]))
            ingress4+=f'''  iifname != "{bridge}" ip daddr {backend} ip saddr != {{ {allowed} }} tcp dport {{ {ports} }} counter drop comment "cheesetrap:ingress4"\n'''
    return f'''# Installation-owned rules only. Never flush the host ruleset.
table inet {table} {{
 comment "{owner}"
 chain ingress {{
  type filter hook prerouting priority -310; policy accept;
{ingress4}  meta nfproto ipv6 fib daddr type local tcp dport {{ {ports} }} counter drop comment "cheesetrap:ingress6"
 }}
 chain input {{
  type filter hook input priority -10; policy accept;
  iifname "{bridge}" ct direction reply ct state {{ established, related }} counter accept
  iifname "{bridge}" counter drop comment "cheesetrap:input"
  iifname "{management}" ct direction reply ct state {{ established, related }} counter accept
  iifname "{management}" counter drop comment "cheesetrap:api-input"
 }}
 chain forward {{
  type filter hook forward priority -10; policy accept;
  iifname "{bridge}" ct direction reply ct state {{ established, related }} counter accept
  iifname "{bridge}" counter drop comment "cheesetrap:forward"
  iifname "{management}" ct direction reply ct state {{ established, related }} counter accept
  iifname "{management}" counter drop comment "cheesetrap:api-forward"
 }}
}}
table bridge {table} {{
 comment "{owner}"
 chain forward {{
  type filter hook forward priority -10; policy accept;
  meta ibrname "{bridge}" ether type {{ ip, ip6 }} ct direction reply ct state {{ established, related }} counter accept
  meta ibrname "{bridge}" ether type {{ ip, ip6 }} counter drop comment "cheesetrap:bridge"
 }}
}}
'''


def network(c,allow_missing=False):
    n=c['sensor_network']
    if allow_missing and n['name'] not in run(['docker','network','ls','--format','{{.Name}}']).splitlines(): return None
    obj=json.loads(run(['docker','network','inspect',n['name']]))[0]
    ipam=obj.get('IPAM',{}).get('Config',[])
    # Docker 29 serializes the unused allocation subrange as an empty string.
    ipam=[{k:v for k,v in entry.items() if not (k=='IPRange' and v=='')} for entry in ipam]
    if obj.get('Driver')!='bridge' or obj.get('Internal') or obj.get('EnableIPv6') or set(obj.get('Options',{}))!={'com.docker.network.bridge.name'} or obj.get('Labels',{}).get('com.cheesetrap.install')!=c['project'] or obj.get('Options',{}).get('com.docker.network.bridge.name')!=n['bridge'] or ipam!=[{'Subnet':n['subnet'],'Gateway':n['gateway']}]:
        raise ValueError('sensor_network_identity_mismatch')
    return obj


def api_network(c):
    name=c['project']+'-api'
    if name not in run(['docker','network','ls','--format','{{.Name}}']).splitlines():
        # A future Compose bridge must not reuse an unrelated host interface:
        # the guard matches this name before the Docker network is created.
        if (Path('/sys/class/net')/api_bridge(c)).exists(): raise ValueError('api_bridge_name_collision')
        return {}
    obj=json.loads(run(['docker','network','inspect',name]))[0]
    if obj.get('Driver')!='bridge' or obj.get('Internal') or obj.get('EnableIPv6') or obj.get('Labels',{}).get('com.cheesetrap.install')!=c['project'] or obj.get('Options',{})!={'com.docker.network.bridge.name':api_bridge(c)}:
        raise ValueError('api_network_identity_mismatch')
    return obj


def firewall_action(action,c,out):
    policy=firewall(c); table=table_name(c); state=Path(out)/'firewall-state.json'
    if action=='render': return policy
    net=network(c,allow_missing=action=='remove') or {}
    api_net=api_network(c)
    tables=json.loads(run(['nft','-j','list','tables']))['nftables']
    present={t['table']['family'] for t in tables if 'table' in t and t['table']['name']==table and t['table']['family'] in ('inet','bridge')}
    if action=='apply':
        if net.get('Containers') or api_net.get('Containers') or present: raise ValueError('stop_sensors_and_remove_existing_owned_guard_first')
        run(['nft','-c','-f','-'],policy)
        run(['nft','-f','-'],policy)
        snapshots={family:run(['nft','-s','list','table',family,table]) for family in ('inet','bridge')}
        state.write_text(json.dumps({'policy_sha256':hashlib.sha256(policy.encode()).hexdigest(),'tables':snapshots}))
        state.chmod(0o600)
    elif action=='check':
        if present!={'inet','bridge'}: raise ValueError('guard_missing')
        expected=json.loads(state.read_text())
        if expected['policy_sha256']!=hashlib.sha256(policy.encode()).hexdigest(): raise ValueError('guard_config_changed')
        if any(run(['nft','-s','list','table',family,table])!=expected['tables'][family] for family in ('inet','bridge')): raise ValueError('guard_rules_changed')
    elif action=='remove':
        if net.get('Containers') or api_net.get('Containers'): raise ValueError('stop_and_remove_sensor_and_api_containers_before_guard_removal')
        # Idempotent cleanup checks ownership even if only one table remains.
        for family in sorted(present):
            obj=json.loads(run(['nft','-j','list','table',family,table]))
            records=[r['table'] for r in obj['nftables'] if 'table' in r]
            if len(records)!=1 or records[0].get('comment')!='cheesetrap:'+c['project']: raise ValueError('refusing_unowned_table_removal')
        if present: run(['nft','-f','-'],''.join(f'delete table {family} {table}\n' for family in sorted(present)))
        state.unlink(missing_ok=True)
    else: raise ValueError('unknown_firewall_action')
    return action+'_ok\n'
