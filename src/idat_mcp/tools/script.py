from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_exec_script(source: str) -> str:
        """Execute IDAPython source in the current worker.

        The script runs with full IDA module access in the open database context.
        Assign to `result` to return a JSON-serializable value.
        stdout/stderr are captured and returned.
        """
        return ctx.call("exec_script", source=source)
