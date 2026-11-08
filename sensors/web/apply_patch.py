"""Apply only the two reviewed hunks to exact pinned upstream bytes; fail closed."""
import hashlib
from pathlib import Path

root = Path('/opencanary')
expected = {
    'http.py': 'fb90b08e1893a4d975aada1dfe7b4fcfc02633ae90870a411285295f63be97dc',
    'https.py': '83a5e42462dc264e02b572e42b3d08de510853ef5f133a0cbb1cf52ca447edd5',
}
lines = Path(__file__).with_name('request-evidence.patch').read_text().splitlines(True)
for name, digest in expected.items():
    target = root / 'opencanary/modules' / name
    source = target.read_bytes()
    if hashlib.sha256(source).hexdigest() != digest:
        raise SystemExit('upstream source changed: ' + name)
    start = lines.index('--- a/opencanary/modules/' + name + '\n') + 3
    end = next((i for i in range(start, len(lines)) if lines[i].startswith('--- ')), len(lines))
    hunk = lines[start:end]
    if any(not line.startswith((' ', '+', '-')) for line in hunk):
        raise SystemExit('only one exact context hunk per file is supported')
    old = ''.join(line[1:] for line in hunk if line.startswith((' ', '-')))
    new = ''.join(line[1:] for line in hunk if line.startswith((' ', '+')))
    text = source.decode()
    if text.count(old) != 1:
        raise SystemExit('patch context mismatch: ' + name)
    target.write_text(text.replace(old, new, 1))
