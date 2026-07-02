from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_get_xrefs_to(address: str, limit: int = 100) -> str:
        """List cross-references to an address in the default database."""
        return ctx.call("get_xrefs_to", address=address, limit=limit)

    @ctx.tool()
    def ida_get_xrefs_from(address: str, limit: int = 100) -> str:
        """List cross-references from an address in the default database."""
        return ctx.call("get_xrefs_from", address=address, limit=limit)
