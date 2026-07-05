from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Callable

from idat_mcp.worker import spawn_worker


@dataclass
class WorkerEntry:
    path: str
    process: Any
    conn: Connection
    lock: threading.Lock


class DatabasePool:
    """Manage one idalib worker process per open database."""

    def __init__(
        self,
        ida_dir: str,
        max_workers: int | None = None,
        debug: bool = False,
        debug_log: Callable[[str], None] | None = None,
    ) -> None:
        self.ida_dir = ida_dir
        self.max_workers = max_workers
        self.debug = debug
        self._debug_log = debug_log
        self._workers: dict[str, WorkerEntry] = {}
        self._default_database: str | None = None
        self._pool_lock = threading.Lock()

    def list_databases(self) -> dict[str, Any]:
        with self._pool_lock:
            databases = [
                {
                    "path": path,
                    "is_default": path == self._default_database,
                }
                for path in sorted(self._workers.keys())
            ]
            return {
                "count": len(databases),
                "databases": databases,
            }

    def set_default_database(self, database: str) -> dict[str, Any]:
        key = self._normalize_path(database)
        with self._pool_lock:
            if key not in self._workers:
                open_paths = ", ".join(sorted(self._workers.keys())) or "(none)"
                raise KeyError(f"Database not open: {key}. Open databases: {open_paths}")
            self._default_database = key
            return {"path": key, "is_default": True, "status": "selected"}

    def _ensure_default_after_open(self, key: str) -> None:
        if self._default_database is None or self._default_database not in self._workers:
            self._default_database = key
        else:
            # Newly opened database becomes the active default.
            self._default_database = key

    def _ensure_default_after_close(self) -> None:
        if self._default_database in self._workers:
            return
        if self._workers:
            self._default_database = next(iter(sorted(self._workers.keys())))
        else:
            self._default_database = None

    def open_count(self) -> int:
        with self._pool_lock:
            return len(self._workers)

    def _normalize_path(self, path: str) -> str:
        return str(Path(path).expanduser().resolve())

    def _log_worker(self, message: str) -> None:
        if self._debug_log is not None:
            self._debug_log(message)

    @staticmethod
    def _describe_payload(payload: dict[str, Any]) -> str:
        cmd = payload.get("cmd", "?")
        if cmd == "call":
            return f"call {payload.get('method', '?')}"
        if cmd == "open":
            recreate = payload.get("recreate", False)
            return f"open recreate={recreate}"
        if cmd == "close":
            return f"close save={payload.get('save', True)}"
        return cmd

    def _request(self, entry: WorkerEntry, payload: dict[str, Any]) -> Any:
        action = self._describe_payload(payload)
        started = time.perf_counter()
        if self.debug:
            self._log_worker(
                f"[debug worker] >>> {action} path={entry.path}"
            )
        with entry.lock:
            entry.conn.send(payload)
            response = entry.conn.recv()
        if self.debug:
            elapsed = time.perf_counter() - started
            if response.get("ok"):
                summary = self._summarize_worker_result(response.get("result"))
                self._log_worker(
                    f"[debug worker] <<< {action} OK ({elapsed:.3f}s){summary} path={entry.path}"
                )
            else:
                error = response.get("error", "Unknown worker error")
                self._log_worker(
                    f"[debug worker] !!! {action} FAILED ({elapsed:.3f}s): {error} path={entry.path}"
                )
        if not response.get("ok"):
            error = response.get("error", "Unknown worker error")
            raise RuntimeError(error)
        return response["result"]

    @staticmethod
    def _summarize_worker_result(result: Any) -> str:
        if not isinstance(result, dict):
            return ""
        hints: list[str] = []
        for key in ("status", "count", "path", "user_functions", "saved"):
            if key in result:
                hints.append(f"{key}={result[key]!r}")
        if not hints:
            return ""
        return " | " + ", ".join(hints)

    def _remove_worker(self, path: str) -> None:
        entry = self._workers.pop(path, None)
        if entry is None:
            return
        try:
            self._request(entry, {"cmd": "shutdown"})
        except Exception:
            pass
        entry.conn.close()
        entry.process.join(timeout=10)
        if entry.process.is_alive():
            entry.process.terminate()

    def open_database(
        self,
        path: str,
        recreate: bool = False,
    ) -> dict[str, Any]:
        key = self._normalize_path(path)

        with self._pool_lock:
            if key in self._workers:
                self._ensure_default_after_open(key)
                return {
                    "path": key,
                    "auto_analysis": True,
                    "status": "already_open",
                    "is_default": key == self._default_database,
                }

            if self.max_workers is not None and len(self._workers) >= self.max_workers:
                raise RuntimeError(
                    f"Maximum number of open databases reached ({self.max_workers}). "
                    "Close an existing database or increase IDAT_MCP_MAX_WORKERS."
                )

            process, conn = spawn_worker(self.ida_dir)
            entry = WorkerEntry(path=key, process=process, conn=conn, lock=threading.Lock())
            try:
                result = self._request(
                    entry,
                    {
                        "cmd": "open",
                        "path": key,
                        "recreate": recreate,
                    },
                )
            except Exception:
                conn.close()
                process.terminate()
                raise

            self._workers[key] = entry
            self._ensure_default_after_open(key)
            result["is_default"] = True
            return result

    def close_database(self, database: str | None = None, save: bool = True) -> dict[str, Any]:
        with self._pool_lock:
            if not self._workers:
                return {"status": "closed", "saved": False}

            if database is None:
                if self._default_database is not None and self._default_database in self._workers:
                    key = self._default_database
                elif len(self._workers) == 1:
                    key = next(iter(self._workers))
                else:
                    raise RuntimeError(
                        "No default database selected. Call ida_select_database first."
                    )
            else:
                key = self._normalize_path(database)

            if key not in self._workers:
                raise KeyError(f"Database is not open: {key}")

            result = self._request(self._workers[key], {"cmd": "close", "save": save})
            self._remove_worker(key)
            self._ensure_default_after_close()
            result["path"] = key
            return result

    def resolve_database(self, database: str | None = None) -> str:
        with self._pool_lock:
            if not self._workers:
                raise RuntimeError("No database is open. Call ida_open_database first.")

            if database is not None:
                key = self._normalize_path(database)
                if key not in self._workers:
                    open_paths = ", ".join(sorted(self._workers.keys()))
                    raise KeyError(f"Database not open: {key}. Open databases: {open_paths}")
                return key

            if self._default_database is not None and self._default_database in self._workers:
                return self._default_database

            if len(self._workers) == 1:
                return next(iter(self._workers))

            raise RuntimeError(
                "No default database selected. Call ida_select_database to choose one."
            )

    def call(self, method: str, **kwargs: Any) -> Any:
        key = self.resolve_database()
        with self._pool_lock:
            entry = self._workers[key]
        return self._request(entry, {"cmd": "call", "method": method, "kwargs": kwargs})

    def shutdown(self) -> None:
        with self._pool_lock:
            for key in list(self._workers.keys()):
                self._remove_worker(key)


_pool: DatabasePool | None = None
_pool_lock = threading.Lock()


def get_pool(
    ida_dir: str,
    max_workers: int | None = None,
    debug: bool = False,
    debug_log: Callable[[str], None] | None = None,
) -> DatabasePool:
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = DatabasePool(
                ida_dir=ida_dir,
                max_workers=max_workers,
                debug=debug,
                debug_log=debug_log,
            )
        return _pool


def shutdown_pool() -> None:
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.shutdown()
            _pool = None
