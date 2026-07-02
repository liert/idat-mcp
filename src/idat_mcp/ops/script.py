from __future__ import annotations

import contextlib
import io
import traceback
from typing import Any


def exec_script(source: str) -> dict[str, Any]:
    """Execute IDAPython source in the current worker context."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    namespace: dict[str, Any] = {"__name__": "__idat_mcp_script__", "result": None}

    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exec(source, namespace, namespace)
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "result": namespace.get("result"),
        }

    return {
        "ok": True,
        "stdout": stdout.getvalue(),
        "stderr": stderr.getvalue(),
        "result": namespace.get("result"),
    }


OPERATIONS = {
    "exec_script": exec_script,
}
