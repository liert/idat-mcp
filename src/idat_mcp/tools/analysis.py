from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_find_call_path(
        start_func: str,
        end_func: str,
        max_depth: int = 10,
        max_paths: int = 5,
    ) -> str:
        """Search call-graph paths from start_func to end_func.

        Uses BFS over direct call edges to find the shortest path, then collects a
        few alternate paths within max_depth. Function arguments accept names or
        addresses.
        """
        return ctx.call(
            "find_call_path",
            start_func=start_func,
            end_func=end_func,
            max_depth=max_depth,
            max_paths=max_paths,
        )

    @ctx.tool()
    def ida_get_backward_slice(address: str, variable_name: str, limit: int = 100) -> str:
        """Backward-slice a local variable from a sink address using Hex-Rays ctree.

        Given an address (for example a dangerous call site) and a local variable
        name (for example size or src), returns the decompiled statements that
        influence that variable at the sink. Requires Hex-Rays.
        """
        return ctx.call(
            "get_backward_slice",
            address=address,
            variable_name=variable_name,
            limit=limit,
        )

    @ctx.tool()
    def ida_resolve_indirect_calls(
        function_address: str,
        add_xrefs: bool = True,
        limit: int = 50,
    ) -> str:
        """Resolve indirect call sites in a function and optionally add code xrefs.

        Scans for register/memory call targets (for example BLR on AArch64), traces
        recent assignments to infer possible callee addresses, and can call add_cref
        to connect recovered control flow in the IDB.
        """
        return ctx.call(
            "resolve_indirect_calls",
            function_address=function_address,
            add_xrefs=add_xrefs,
            limit=limit,
        )
