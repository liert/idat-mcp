from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_search_strings(min_length: int = 4, limit: int = 200) -> str:
        """Search for strings in the default database."""
        return ctx.call("search_strings", min_length=min_length, limit=limit)

    @ctx.tool()
    def ida_search_bytes(pattern: str, limit: int = 100) -> str:
        """Search for a byte pattern (e.g. '48 8B ?? 24') in the default database."""
        return ctx.call("search_bytes", pattern=pattern, limit=limit)

    @ctx.tool()
    def ida_search_immediate(value: int, limit: int = 100) -> str:
        """Search for an immediate value in instructions (decimal or 0x hex)."""
        return ctx.call("search_immediate", value=value, limit=limit)
