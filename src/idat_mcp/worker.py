from __future__ import annotations

import os
import traceback
from multiprocessing.connection import Connection
from typing import Any

from idat_mcp.ops import OPERATIONS, close_database, open_database


def worker_main(conn: Connection, ida_dir: str) -> None:
    """Run one idalib worker process bound to a single database."""
    os.environ["IDADIR"] = ida_dir
    database_path: str | None = None

    try:
        import idapro  # noqa: F401 — must be first IDA import
    except Exception as exc:
        conn.send({"ok": False, "error": f"Failed to initialize idapro: {exc}"})
        conn.close()
        return

    while True:
        try:
            message = conn.recv()
        except EOFError:
            break

        cmd = message.get("cmd")
        try:
            if cmd == "shutdown":
                if database_path is not None:
                    close_database(save=True)
                    database_path = None
                conn.send({"ok": True, "result": {"status": "shutdown"}})
                break

            if cmd == "open":
                if database_path is not None:
                    close_database(save=True)
                result = open_database(
                    message["path"],
                    recreate=message.get("recreate", False),
                )
                database_path = result["path"]
                conn.send({"ok": True, "result": result})
                continue

            if cmd == "close":
                if database_path is None:
                    conn.send({"ok": True, "result": {"status": "closed", "saved": False}})
                    continue
                previous = database_path
                result = close_database(save=message.get("save", True))
                database_path = None
                result["path"] = previous
                conn.send({"ok": True, "result": result})
                continue

            if cmd == "ping":
                conn.send({"ok": True, "result": {"path": database_path, "alive": True}})
                continue

            if cmd == "call":
                if database_path is None:
                    raise RuntimeError("Worker has no open database")

                method = message["method"]
                fn = OPERATIONS.get(method)
                if fn is None:
                    raise ValueError(f"Unknown operation: {method}")

                kwargs = dict(message.get("kwargs", {}))
                if method == "get_database_info":
                    kwargs["database_path"] = database_path

                result = fn(**kwargs)
                conn.send({"ok": True, "result": result})
                continue

            raise ValueError(f"Unknown command: {cmd}")

        except Exception as exc:
            conn.send(
                {
                    "ok": False,
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                }
            )

    conn.close()


def spawn_worker(ida_dir: str) -> tuple[Any, Connection]:
    from multiprocessing import Pipe, get_context

    ctx = get_context("spawn")
    parent_conn, child_conn = Pipe(duplex=True)
    process = ctx.Process(
        target=worker_main,
        args=(child_conn, ida_dir),
        daemon=True,
    )
    process.start()
    child_conn.close()
    return process, parent_conn
