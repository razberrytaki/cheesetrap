#!/usr/bin/env python3
import argparse
import sys
from install_lib import load,check
p=argparse.ArgumentParser(description='Read-only Linux installation preflight; preserve SSH_CONNECTION through sudo.')
p.add_argument('--config',required=True);p.add_argument('--output',required=True)
a=p.parse_args()
try:
    check(load(a.config),a.output);print('installation_preflight_passed')
except ValueError as e:
    # Helper errors contain static codes; IP parsing errors may include nonsecret config.
    print('installation_preflight_failed: '+str(e),file=sys.stderr);sys.exit(1)
except (OSError,KeyError,TypeError):
    print('installation_preflight_failed: host_inspection_failed',file=sys.stderr);sys.exit(1)
