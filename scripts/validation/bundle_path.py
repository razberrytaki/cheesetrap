"""Side-effect-free path validation for the prepared ingress acceptance bundle."""
from pathlib import Path
import re


def resolve_bundle_path(path):
    """Return the resolved directory, retaining the installer's project policy."""
    base = Path(path).resolve()
    if base == Path(base.anchor) or not base.is_dir():
        raise ValueError('bundle_directory_required')
    # Keep this character/length rule aligned with install_lib.validate().
    if (not base.name.startswith('cheesetrap-f0102-')
            or not re.fullmatch(r'cheesetrap-[a-z0-9][a-z0-9-]{0,36}', base.name)):
        raise ValueError('bundle_project_invalid')
    return base
