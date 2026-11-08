#!/usr/bin/env python3
"""Owned nonce responders and metadata-route checks for isolated sensor tests."""
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import time

META = '169.254.169.254'


def command(*args, input=None, check=True):
    p = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    if check and p.returncode:
        raise RuntimeError(f'{args[0:3]} failed ({p.returncode}): {p.stderr.strip()}')
    return p.stdout


def js(*args):
    return json.loads(command(*args))


def validate_metadata_route(routes, lookup, peer):
    exact = lambda r: r.get('dst') in (META, META + '/32')
    if not any(exact(r) and r.get('gateway') == peer and r.get('dev') == 'eth0' and r.get('metric') == 1 for r in routes):
        raise ValueError('metadata exact route is not through the isolated mock')
    if not any(exact(r) and r.get('type') == 'prohibit' and r.get('metric') == 32760 for r in routes):
        raise ValueError('metadata prohibit fallback missing')
    if len(lookup) != 1 or lookup[0].get('gateway') != peer or lookup[0].get('dev') != 'eth0':
        raise ValueError('metadata route lookup escapes isolated mock')


def probe(cid, executable, address, port, nonce):
    script = '''import json,os,socket
x=json.loads(%r);r={'echo':'','error':'','netns':os.readlink('/proc/self/ns/net')}
s=socket.socket();s.settimeout(1.25);s.bind(('0.0.0.0',0));r['local_port']=s.getsockname()[1]
try:
 s.connect((x['address'],x['port']));s.sendall((x['nonce']+'\\n').encode());r['echo']=s.recv(1024).decode().strip()
except Exception as e:r['error']=type(e).__name__
finally:s.close()
print(json.dumps(r))
''' % json.dumps(dict(address=address,port=port,nonce=nonce))
    return json.loads(command('docker','exec','-i',cid,executable,'-',input=script))


def serve(config):
    cfg=json.loads(Path(config).read_text());sel=selectors.DefaultSelector()
    log=open(cfg['log'],'a',buffering=1)
    for address,port in cfg['listeners']:
        sock=socket.socket();sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.bind((address,port));sock.listen(16);sel.register(sock,selectors.EVENT_READ)
    os.setgroups([]);os.setgid(65534);os.setuid(65534)
    while True:
        for key,_ in sel.select():
            conn,peer=key.fileobj.accept();conn.settimeout(2)
            try:
                data=conn.recv(512)
                nonce=data.decode('ascii').strip()
                if not re.fullmatch(r'[0-9a-f]{48}(-alive|-blocked)?',nonce):continue
                address,port=conn.getsockname()
                log.write(json.dumps(dict(address=address,port=port,nonce=nonce,peer=peer,time=time.time()))+'\n')
                conn.sendall(data)
            except (OSError,UnicodeError):pass
            finally:conn.close()


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != 'serve':
        sys.exit('usage: network_fixture.py serve CONFIG')
    serve(sys.argv[2])
