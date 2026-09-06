#!/usr/bin/env python3
"""Exec the localscaled binary shipped beside this launcher."""
from pathlib import Path
import os
import sys


BUNDLE_ROOT = Path(__file__).resolve().parent
AGENT = BUNDLE_ROOT / "localscaled"

if not AGENT.is_file() or not os.access(AGENT, os.X_OK):
    raise SystemExit(f"missing executable agent: {AGENT}")
os.execv(str(AGENT), [str(AGENT), *sys.argv[1:]])
