from idat_mcp.tools import analysis, database, functions, search, symbols, variables, xrefs
from idat_mcp.tools import annotations as annotation_tools
from idat_mcp.tools import script as script_tools
from idat_mcp.tools import types as type_tools
from idat_mcp.tools._base import ToolContext


def register_tools(
    mcp,
    ida_dir: str,
    max_workers: int | None,
    debug: bool = False,
) -> None:
    ctx = ToolContext(mcp, ida_dir, max_workers, debug=debug)
    database.register(ctx)
    functions.register(ctx)
    analysis.register(ctx)
    xrefs.register(ctx)
    search.register(ctx)
    symbols.register(ctx)
    annotation_tools.register(ctx)
    type_tools.register(ctx)
    variables.register(ctx)
    script_tools.register(ctx)
