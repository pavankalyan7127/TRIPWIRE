#!/usr/bin/env python3
"""Tripwire Root Demo Entrypoint.

Delegates execution to Backend/demo.py.
"""

import os
import runpy
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent / "Backend"
demo_script = backend_dir / "demo.py"

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

os.chdir(backend_dir)

if __name__ == "__main__":
    runpy.run_path(str(demo_script), run_name="__main__")
