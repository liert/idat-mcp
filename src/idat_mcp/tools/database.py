from __future__ import annotations

from idat_mcp.tools._base import ToolContext


def register(ctx: ToolContext) -> None:
    @ctx.tool()
    def ida_open_database(path: str, recreate: bool = False) -> str:
        """Open a binary file in IDA and run auto-analysis.

        The opened database becomes the default target for subsequent tools.
        Other open databases are kept in separate workers.
        Set recreate=True to delete the old IDB and analyze from scratch.
        """
        return ctx.json(ctx.pool().open_database(path, recreate=recreate))

    @ctx.tool()
    def ida_analyze_database() -> str:
        """Run full auto-analysis on the default database.

        Use when ida_list_functions returns no user functions but imports exist.
        """
        return ctx.call("analyze_database")

    @ctx.tool()
    def ida_close_database(database: str | None = None, save: bool = True) -> str:
        """Close an open database. Closes the default database when database is omitted."""
        return ctx.json(ctx.pool().close_database(database, save))

    @ctx.tool()
    def ida_list_databases() -> str:
        """List all open databases. Each entry includes is_default for the active target."""
        return ctx.json(ctx.pool().list_databases())

    @ctx.tool()
    def ida_select_database(database: str) -> str:
        """Select the default database used by all analysis tools."""
        return ctx.json(ctx.pool().set_default_database(database))

    @ctx.tool()
    def ida_get_database_info() -> str:
        """Return metadata about the default database."""
        return ctx.call("get_database_info")

    @ctx.tool()
    def ida_list_segments() -> str:
        """List memory segments in the default database."""
        return ctx.call("list_segments")
