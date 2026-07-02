from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_list_structs(limit: int = 200) -> str:
        """List local structure types in the default database."""
        return ctx.call("list_structs", limit=limit)

    @ctx.tool()
    def ida_get_struct_members(name: str) -> str:
        """Get members of a structure type by name."""
        return ctx.call("get_struct_members", name=name)

    @ctx.tool()
    def ida_get_type_at_address(address: str) -> str:
        """Get the type annotation applied to an address."""
        return ctx.call("get_type_at_address", address=address)

    @ctx.tool()
    def ida_set_type_at_address(address: str, type_decl: str) -> str:
        """Apply a C type declaration to a data address or global.

        Automatically reanalyzes affected functions and invalidates decompiler cache.
        """
        return ctx.call("set_type_at_address", address=address, type_decl=type_decl)

    @ctx.tool()
    def ida_apply_function_type(address: str, prototype: str) -> str:
        """Apply a C function prototype to a function (e.g. 'int __cdecl foo(int a)').

        Automatically reanalyzes the function, its callers, and invalidates decompiler cache.
        """
        return ctx.call("apply_function_type", address=address, prototype=prototype)

    @ctx.tool()
    def ida_create_struct(declaration: str) -> str:
        """Create or update structure types from a C declaration string."""
        return ctx.call("create_struct", declaration=declaration)

    @ctx.tool()
    def ida_add_struct_member(
        struct_name: str,
        member_name: str,
        member_type: str,
        offset: str | int | None = None,
    ) -> str:
        """Add a member to an existing structure. Offset defaults to end of struct."""
        return ctx.call(
            "add_struct_member",
            struct_name=struct_name,
            member_name=member_name,
            member_type=member_type,
            offset=offset,
        )

    @ctx.tool()
    def ida_apply_struct_at_address(address: str, struct_name: str) -> str:
        """Apply a named structure type to a memory address.

        Automatically reanalyzes affected functions and invalidates decompiler cache.
        """
        return ctx.call("apply_struct_at_address", address=address, struct_name=struct_name)

    @ctx.tool()
    def ida_rename_local_variable(function_address: str, old_name: str, new_name: str) -> str:
        """Rename a decompiler local variable (requires Hex-Rays)."""
        return ctx.call(
            "rename_local_variable",
            function_address=function_address,
            old_name=old_name,
            new_name=new_name,
        )

    @ctx.tool()
    def ida_set_local_variable_type(function_address: str, variable_name: str, type_decl: str) -> str:
        """Set a decompiler local variable type (requires Hex-Rays).

        Automatically reanalyzes the function and invalidates decompiler cache.
        """
        return ctx.call(
            "set_local_variable_type",
            function_address=function_address,
            variable_name=variable_name,
            type_decl=type_decl,
        )
