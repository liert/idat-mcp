#!/usr/bin/env python3
"""Launch the idat-mcp HTTP server.

Example:
    python server.py --ida-dir /home/kali/ida-pro-9.3
    python server.py --ida-dir /home/kali/ida-pro-9.3 --host 0.0.0.0 --port 8745
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from idat_mcp.__main__ import main

if __name__ == "__main__":
    main()
