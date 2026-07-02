from __future__ import annotations

from typing import Any

from idat_mcp.ops.common import resolve_ea, resolve_function


def get_comment(address: str) -> dict[str, Any]:
    import ida_bytes
    import ida_funcs

    ea = resolve_ea(address)
    func = ida_funcs.get_func(ea)
    return {
        "address": hex(ea),
        "regular_comment": ida_bytes.get_cmt(ea, False) or "",
        "repeatable_comment": ida_bytes.get_cmt(ea, True) or "",
        "function_comment": ida_funcs.get_func_cmt(func, False) if func else "",
        "function_repeatable_comment": ida_funcs.get_func_cmt(func, True) if func else "",
    }


def set_comment(address: str, comment: str, repeatable: bool = False) -> dict[str, Any]:
    import ida_bytes

    ea = resolve_ea(address)
    if not ida_bytes.set_cmt(ea, comment, repeatable):
        raise RuntimeError(f"Failed to set comment at {hex(ea)}")

    return {
        "address": hex(ea),
        "comment": comment,
        "repeatable": repeatable,
    }


def rename_function(address: str, new_name: str) -> dict[str, str]:
    import ida_funcs
    import ida_name

    func = resolve_function(address)
    old_name = ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea) or ""
    if not ida_name.set_name(func.start_ea, new_name, ida_name.SN_CHECK):
        raise RuntimeError(f"Failed to rename function at {hex(func.start_ea)}")

    return {"address": hex(func.start_ea), "old_name": old_name, "new_name": new_name}


OPERATIONS = {
    "get_comment": get_comment,
    "set_comment": set_comment,
    "rename_function": rename_function,
}
