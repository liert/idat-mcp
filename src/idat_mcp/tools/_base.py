from __future__ import annotations

import functools
import json
import sys
import time
from typing import Any, Callable

from idat_mcp.pool import get_pool


class ToolContext:
    def __init__(
        self,
        mcp: Any,
        ida_dir: str,
        max_workers: int | None,
        debug: bool = False,
    ) -> None:
        self.mcp = mcp
        self.ida_dir = ida_dir
        self.max_workers = max_workers
        self.debug = debug
        self._pool = None

    def pool(self):
        if self._pool is None:
            self._pool = get_pool(self.ida_dir, self.max_workers)
        return self._pool

    def call(self, op: str, **kwargs: Any) -> str:
        return json.dumps(self.pool().call(op, **kwargs), indent=2)

    def json(self, value: Any) -> str:
        return json.dumps(value, indent=2)

    def _log_debug(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    def _wrap_tool(self, fn: Callable[..., str]) -> Callable[..., str]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> str:
            name = fn.__name__
            self._log_debug(f"[debug] tool start: {name}")
            started = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            except Exception:
                elapsed = time.perf_counter() - started
                self._log_debug(f"[debug] tool failed: {name} ({elapsed:.3f}s)")
                raise
            else:
                elapsed = time.perf_counter() - started
                self._log_debug(f"[debug] tool done: {name} ({elapsed:.3f}s)")

        return wrapper

    def tool(self):
        mcp_tool = self.mcp.tool()
        if not self.debug:
            return mcp_tool
        return lambda fn: mcp_tool(self._wrap_tool(fn))
