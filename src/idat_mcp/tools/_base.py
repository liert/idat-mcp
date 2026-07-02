from __future__ import annotations

import json
from typing import Any

from idat_mcp.pool import get_pool


class ToolContext:
    def __init__(self, mcp: Any, ida_dir: str, max_workers: int | None) -> None:
        self.mcp = mcp
        self.ida_dir = ida_dir
        self.max_workers = max_workers
        self._pool = None

    def pool(self):
        if self._pool is None:
            self._pool = get_pool(self.ida_dir, self.max_workers)
        return self._pool

    def call(self, op: str, **kwargs: Any) -> str:
        return json.dumps(self.pool().call(op, **kwargs), indent=2)

    def json(self, value: Any) -> str:
        return json.dumps(value, indent=2)

    def tool(self):
        return self.mcp.tool()
