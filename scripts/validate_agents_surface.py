#!/usr/bin/env python3
"""Validate cheesetrap's scoped instructions and local references.

Usage:
  python3 -B scripts/validate_agents_surface.py [--root DIR]

Checks required project instructions, Markdown links and documented script paths.
Does not execute the referenced commands or verify runtime behavior.
"""
import argparse
import re
from urllib.parse import unquote
import sys
from pathlib import Path

def _root(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    return parser.parse_args(argv).root.resolve()


def project_main(argv):
    root = _root(argv)
    problems = []
    references = 0
    for name in ('AGENTS.md', 'internal/AGENTS.md', 'web/AGENTS.md'):
        path = root / name
        if not path.is_file():
            problems.append(f'{name}: required scoped instruction file missing')
            continue
        text = path.read_text(encoding='utf-8')
        if not text.strip():
            problems.append(f'{name}: instruction file is empty')
        for target in re.findall(r'\]\(([^)\s]+)\)', text):
            if target.startswith('#') or re.match(r'[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                continue
            references += 1
            local = unquote(target.split('#', 1)[0])
            if not (path.parent / local).exists():
                problems.append(f'{name}: local reference missing: {target}')
        # Commands are documented relative to the repository root. Ignore
        # placeholder examples; never execute the referenced scripts.
        for script in sorted(set(re.findall(r'(?<![\w/])(scripts/[\w/.-]+\.(?:py|mjs|sh))', text))):
            references += 1
            if not (root / script).is_file():
                problems.append(f'{name}: script missing: {script}')
    for problem in problems:
        print('ERROR: ' + problem)
    if problems:
        return 1
    print(f'OK: 3 project instruction files; {references} local references checked. '
          'Runtime behavior was not checked.')
    return 0


if __name__ == "__main__":
    sys.exit(project_main(sys.argv[1:]))
