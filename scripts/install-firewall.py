#!/usr/bin/env python3
import argparse
import sys
from install_lib import load,firewall_action
p=argparse.ArgumentParser(description='Manage only this installation nftables tables; never change SSH or flush.')
p.add_argument('action',choices=['render','apply','check','remove']);p.add_argument('--config',required=True);p.add_argument('--output',required=True)
a=p.parse_args()
try: print(firewall_action(a.action,load(a.config),a.output),end='')
except (ValueError,OSError,KeyError,TypeError):
    print('installation_guard_failed (verify network identity, owned rules, stopped sensors)',file=sys.stderr);sys.exit(1)
