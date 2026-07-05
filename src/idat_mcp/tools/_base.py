from __future__ import annotations

import contextvars
import functools
import inspect
import json
import sys
import threading
import time
from typing import Any, Callable

from idat_mcp.pool import get_pool

_current_debug_id: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "current_debug_id",
    default=None,
)


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
        self._req_counter = 0
        self._req_lock = threading.Lock()

    def pool(self):
        if self._pool is None:
            self._pool = get_pool(
                self.ida_dir,
                self.max_workers,
                debug=self.debug,
                debug_log=self._pool_debug_log if self.debug else None,
            )
        return self._pool

    def _pool_debug_log(self, message: str) -> None:
        req_id = _current_debug_id.get()
        label = f"#{req_id}" if req_id is not None else "#?"
        if message.startswith("[debug worker] "):
            message = message[len("[debug worker] ") :]
        self._log_debug(f"[debug {label}] worker {message}")

    def call(self, op: str, **kwargs: Any) -> str:
        if not self.debug:
            return json.dumps(self.pool().call(op, **kwargs), indent=2)

        req_id = _current_debug_id.get()
        label = f"#{req_id}" if req_id is not None else "#?"
        started = time.perf_counter()
        database = self._safe_default_database()
        self._log_debug(
            f"[debug {label}] op >>> {op} db={database}{self._format_kwargs(kwargs)}"
        )
        try:
            result = self.pool().call(op, **kwargs)
        except Exception as exc:
            elapsed = time.perf_counter() - started
            self._log_debug(
                f"[debug {label}] op !!! {op} FAILED ({elapsed:.3f}s): "
                f"{type(exc).__name__}: {exc}"
            )
            raise
        else:
            elapsed = time.perf_counter() - started
            self._log_debug(
                f"[debug {label}] op <<< {op} OK ({elapsed:.3f}s)"
                f"{self._summarize_payload(result)}"
            )
            return json.dumps(result, indent=2)

    def json(self, value: Any) -> str:
        return json.dumps(value, indent=2)

    def _next_req_id(self) -> int:
        with self._req_lock:
            self._req_counter += 1
            return self._req_counter

    def _safe_default_database(self) -> str:
        try:
            return self.pool().resolve_database()
        except Exception:
            return "(none)"

    def _log_debug(self, message: str) -> None:
        thread_id = threading.get_ident()
        print(f"{message} [thread={thread_id}]", file=sys.stderr, flush=True)

    @staticmethod
    def _format_value(value: Any, max_len: int = 120) -> str:
        if isinstance(value, str):
            text = value.replace("\n", "\\n")
            if len(text) > max_len:
                return repr(text[:max_len] + f"...(+{len(value) - max_len} chars)")
            return repr(text)
        if isinstance(value, (list, tuple)) and len(value) > 8:
            return repr(list(value[:8]) + [f"...(+{len(value) - 8} items)"])
        return repr(value)

    def _format_kwargs(self, kwargs: dict[str, Any]) -> str:
        if not kwargs:
            return ""
        parts = [f"{key}={self._format_value(value)}" for key, value in kwargs.items()]
        return " | " + ", ".join(parts)

    def _format_tool_args(self, fn: Callable[..., str], args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        try:
            bound = inspect.signature(fn).bind_partial(*args, **kwargs)
            bound.apply_defaults()
            params = {
                key: value
                for key, value in bound.arguments.items()
                if value is not inspect.Parameter.empty
            }
        except (TypeError, ValueError):
            params = dict(kwargs)
            if args:
                params["args"] = args
        return self._format_kwargs(params)

    @staticmethod
    def _summarize_payload(payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        hints: list[str] = []
        for key in (
            "status",
            "count",
            "path",
            "function",
            "name",
            "found",
            "block_count",
            "instruction_count",
            "errors",
        ):
            if key in payload:
                hints.append(f"{key}={payload[key]!r}")
        if not hints:
            return ""
        return " | " + ", ".join(hints[:6])

    def _summarize_result(self, result: str) -> str:
        try:
            payload = json.loads(result)
        except json.JSONDecodeError:
            if len(result) > 80:
                return f" | result={len(result)} chars"
            return f" | result={result!r}"
        return self._summarize_payload(payload)

    def _wrap_tool(self, fn: Callable[..., str]) -> Callable[..., str]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> str:
            req_id = self._next_req_id()
            token = _current_debug_id.set(req_id)
            name = fn.__name__
            args_text = self._format_tool_args(fn, args, kwargs)
            self._log_debug(f"[debug #{req_id}] >>> {name}{args_text}")
            started = time.perf_counter()
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                elapsed = time.perf_counter() - started
                self._log_debug(
                    f"[debug #{req_id}] !!! {name} FAILED ({elapsed:.3f}s): "
                    f"{type(exc).__name__}: {exc}"
                )
                raise
            else:
                elapsed = time.perf_counter() - started
                self._log_debug(
                    f"[debug #{req_id}] <<< {name} OK ({elapsed:.3f}s)"
                    f"{self._summarize_result(result)}"
                )
                return result
            finally:
                _current_debug_id.reset(token)

        return wrapper

    def tool(self):
        mcp_tool = self.mcp.tool()
        if not self.debug:
            return mcp_tool
        return lambda fn: mcp_tool(self._wrap_tool(fn))
