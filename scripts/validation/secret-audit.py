# Executed as the sensor's actual configured uid through trusted docker exec.
# Metadata/access checks only. Never open or print credential contents.
import json
import os

paths = [
    '/run/secrets', '/run/credentials', '/run/cheesetrap', '/var/run/secrets',
    '/etc/cheesetrap', '/.env', '/app/.env',
    '/root/.ssh', '/root/.aws', '/root/.oci',
    '/home/ubuntu/.ssh', '/home/ubuntu/.aws', '/home/ubuntu/.oci',
    '/cowrie/.ssh', '/cowrie/.aws', '/cowrie/.oci',
    '/home/nobody/.ssh', '/home/nobody/.aws', '/home/nobody/.oci',
]
result = {'uid': os.geteuid(), 'netns': os.readlink('/proc/self/ns/net'), 'paths': []}
for path in paths:
    try:
        os.stat(path)
        status = 'readable' if os.access(path, os.R_OK) else 'unreadable'
    except FileNotFoundError:
        status = 'absent'
    except PermissionError:
        status = 'unreadable'
    result['paths'].append({'path': path, 'status': status})
print(json.dumps(result))
