from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_list_imports(limit: int = 500) -> str:
        """List imported functions in the default database."""
        return ctx.call("list_imports", limit=limit)

    @ctx.tool()
    def ida_list_exports(limit: int = 500) -> str:
        """List exported symbols / entry points in the default database."""
        return ctx.call("list_exports", limit=limit)

    @ctx.tool()
    def ida_list_global_names(filter: str = "", limit: int = 200) -> str:
        """List global names in the default database."""
        return ctx.call("list_global_names", filter=filter, limit=limit)

    @ctx.tool()
    def ida_demangle(name: str) -> str:
        """Demangle a C++ symbol name."""
        return ctx.call("demangle", name=name)
