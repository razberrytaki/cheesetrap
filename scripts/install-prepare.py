#!/usr/bin/env python3
import argparse
from pathlib import Path
import sys
from install_lib import load, prepare, refresh_sources
p=argparse.ArgumentParser(description='Prepare a NEW private installation; JSON-compatible YAML configuration.')
p.add_argument('--config',required=True);p.add_argument('--output',required=True);p.add_argument('--refresh-sources',action='store_true')
a=p.parse_args()
try:
    c=load(a.config)
    if a.refresh_sources:
        if load(Path(a.output)/'install.json')!=c: raise ValueError('prepared_configuration_mismatch')
        refresh_sources(Path(a.output))
    else: prepare(c,Path(a.output))
    print('sources_refreshed' if a.refresh_sources else 'installation_prepared')
except (ValueError,OSError,KeyError,TypeError):
    print('installation_prepare_failed (check settings, ownership, output existence, archive limit)',file=sys.stderr);sys.exit(1)
