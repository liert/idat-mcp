from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_list_functions(
        offset: int = 0,
        limit: int = 100,
        filter: str = "",
        include_imports: bool = False,
    ) -> str:
        """List analyzed functions in the default database.

        By default excludes import stubs, PLT thunks, and extern segment functions.
        Set include_imports=True to include them.
        """
        return ctx.call(
            "list_functions",
            offset=offset,
            limit=limit,
            filter=filter,
            include_imports=include_imports,
        )

    @ctx.tool()
    def ida_get_function(name_or_address: str) -> str:
        """Get details for a function by name or address in the default database."""
        return ctx.call("get_function", name_or_address=name_or_address)

    @ctx.tool()
    def ida_decompile_function(address: str) -> str:
        """Decompile a function to pseudocode in the default database (requires Hex-Rays)."""
        return ctx.call("decompile_function", address=address)

    @ctx.tool()
    def ida_disassemble(address: str, size: str | int = 128) -> str:
        """Disassemble instructions starting at an address.

        size is the number of bytes to cover (int or hex string, e.g. 64 or "0x14").
        Pass the size from ida_get_function to disassemble a whole function.
        """
        return ctx.call("disassemble", address=address, size=size)

    @ctx.tool()
    def ida_get_bytes(address: str, size: int = 64) -> str:
        """Read raw bytes from the default database."""
        return ctx.call("get_bytes", address=address, size=size)

    @ctx.tool()
    def ida_get_function_callers(name_or_address: str, limit: int = 100) -> str:
        """List functions that call the given function."""
        return ctx.call("get_function_callers", name_or_address=name_or_address, limit=limit)

    @ctx.tool()
    def ida_get_function_callees(name_or_address: str, limit: int = 100) -> str:
        """List functions called by the given function."""
        return ctx.call("get_function_callees", name_or_address=name_or_address, limit=limit)

    @ctx.tool()
    def ida_get_function_cfg(name_or_address: str) -> str:
        """Get control-flow graph basic blocks for a function."""
        return ctx.call("get_function_cfg", name_or_address=name_or_address)
