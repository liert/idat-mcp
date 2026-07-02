from typing import Any, Callable

from idat_mcp.ops import database, functions, search, symbols, variables, xrefs
from idat_mcp.ops import annotations as annotation_ops
from idat_mcp.ops import script as script_ops
from idat_mcp.ops import types as type_ops
from idat_mcp.ops.database import close_database, open_database

OPERATIONS: dict[str, Callable[..., Any]] = {}
for module in (
    database,
    functions,
    xrefs,
    search,
    symbols,
    annotation_ops,
    type_ops,
    variables,
    script_ops,
):
    OPERATIONS.update(module.OPERATIONS)

__all__ = ["OPERATIONS", "open_database", "close_database"]
