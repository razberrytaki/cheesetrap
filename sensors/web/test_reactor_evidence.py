"""Real epoll/TCP EOF regression; run in the pinned image with --network none.

Uses only container loopback and fixed inert bytes; StringTransport is not used.
"""
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace

from twisted.internet import reactor
from twisted.web.resource import Resource
from twisted.web.server import Request
from opencanary.modules.http import CanaryRequest

spec = importlib.util.spec_from_file_location('request_evidence', Path(__file__).with_name('request_evidence.py'))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)

class Page(Resource):
    isLeaf = True
    def render(self, request):
        return b'ok'

with tempfile.TemporaryDirectory() as directory:
    evidence.OUTPUT = directory + '/events.jsonl'
    listeners = []
    for name, base in [('http', CanaryRequest), ('standard', Request)]:
        site = evidence.evidence_site(Page(), SimpleNamespace(NAME=name, log=lambda *a, **kw: None), base)
        listeners.append((name, reactor.listenTCP(0, site, interface='127.0.0.1')))
    errors = []
    expected = 0
    def client():
        try:
            for name, listener in listeners:
                for i in range(20):
                    with socket.create_connection(('127.0.0.1', listener.getHost().port), timeout=3) as conn:
                        raw = ('POST /partial-%d HTTP/1.1\r\nHost: sensor.test.invalid\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\npartial' % i).encode()
                        conn.sendall(raw)
                        conn.shutdown(socket.SHUT_WR)
                        while conn.recv(4096):
                            pass
        except Exception as error:
            errors.append(repr(error))
        finally:
            reactor.callFromThread(reactor.callLater, .2, reactor.stop)
    reactor.callWhenRunning(lambda: threading.Thread(target=client, daemon=True).start())
    reactor.run()
    assert not errors, errors
    rows = [json.loads(line) for line in Path(evidence.OUTPUT).read_bytes().splitlines()]
    assert len(rows) == 40, (len(rows), [(row['protocol'], row['uri']) for row in rows])
    for row in rows:
        assert row['parse_error'] == 'client_disconnect', row
        assert row['body'] == 'partial', row
        assert row['auto_report_eligible'] is False, row
    print('PASS: 40 real reactor TCP half-closes retained partial request evidence')
