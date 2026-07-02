from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_list_local_variables(function_address: str) -> str:
        """List decompiler local variables for a function (requires Hex-Rays)."""
        return ctx.call("list_local_variables", function_address=function_address)

    @ctx.tool()
    def ida_get_local_variable_xrefs(
        function_address: str,
        variable_name: str,
        limit: int = 100,
    ) -> str:
        """Find decompiler-level uses of a local variable in a function (requires Hex-Rays)."""
        return ctx.call(
            "get_local_variable_xrefs",
            function_address=function_address,
            variable_name=variable_name,
            limit=limit,
        )

    @ctx.tool()
    def ida_get_global_variable_xrefs(name_or_address: str, limit: int = 100) -> str:
        """List cross-references to a global symbol with caller context."""
        return ctx.call("get_global_variable_xrefs", name_or_address=name_or_address, limit=limit)
