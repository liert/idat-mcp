from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_get_comment(address: str) -> str:
        """Get regular/repeatable and function comments at an address."""
        return ctx.call("get_comment", address=address)

    @ctx.tool()
    def ida_set_comment(address: str, comment: str, repeatable: bool = False) -> str:
        """Set a comment at an address in the default database."""
        return ctx.call("set_comment", address=address, comment=comment, repeatable=repeatable)

    @ctx.tool()
    def ida_rename_function(address: str, new_name: str) -> str:
        """Rename a function in the default database."""
        return ctx.call("rename_function", address=address, new_name=new_name)
