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

    @ctx.tool()
    def ida_get_microcode(
        address: str,
        maturity: str = "glbopt1",
        max_blocks: int = 256,
        max_instructions: int = 4096,
    ) -> str:
        """Extract Hex-Rays microcode (mba/mblock/minsn) for a function.

        Returns SSA-style microcode blocks, successor edges, and instruction text.
        Useful for control-flow deobfuscation (for example OLLVM flattening).
        maturity accepts aliases such as locopt, glbopt1, or numeric Hex-Rays levels.
        Requires Hex-Rays.
        """
        return ctx.call(
            "get_microcode",
            address=address,
            maturity=maturity,
            max_blocks=max_blocks,
            max_instructions=max_instructions,
        )

    @ctx.tool()
    def ida_find_crypto_constants(
        add_comments: bool = True,
        limit: int = 100,
        signature_ids: list[str] | None = None,
    ) -> str:
        """Scan the database for common cryptographic magic constants.

        Matches AES S-Boxes, MD5/SHA init vectors, ChaCha20 constants, CRC32
        tables, and related signatures. Optionally adds [Crypto] comments at hits.
        signature_ids limits scanning to specific signature ids when provided.
        """
        return ctx.call(
            "find_crypto_constants",
            add_comments=add_comments,
            limit=limit,
            signature_ids=signature_ids,
        )
