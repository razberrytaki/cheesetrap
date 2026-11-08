#!/usr/bin/env python3
"""Run cheesetrap's project instruction checks (compatibility entry point)."""
import sys

from validate_agents_surface import project_main


if __name__ == "__main__":
    sys.exit(project_main(sys.argv[1:]))
