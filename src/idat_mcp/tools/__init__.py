from __future__ import annotations

from idat_mcp.tools import (
    annotations,
    database,
    functions,
    script,
    search,
    symbols,
    types,
    variables,
    xrefs,
)
from idat_mcp.tools._base import ToolContext


def register_tools(mcp, ida_dir: str, max_workers: int | None) -> None:
    ctx = ToolContext(mcp, ida_dir, max_workers)
    database.register(ctx)
    functions.register(ctx)
    xrefs.register(ctx)
    search.register(ctx)
    symbols.register(ctx)
    annotations.register(ctx)
    types.register(ctx)
    variables.register(ctx)
    script.register(ctx)
