from __future__ import annotations

from typing import Any


def invalidate_decompilation(ea: int) -> bool:
    import ida_funcs
    import ida_hexrays

    func = ida_funcs.get_func(ea)
    if func is None:
        return False
    if not ida_hexrays.init_hexrays_plugin():
        return False
    return bool(ida_hexrays.mark_cfunc_dirty(func.start_ea))


def _function_start(ea: int) -> int | None:
    import ida_funcs

    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    return func.start_ea


def refresh_function_analysis(func_ea: int) -> None:
    import ida_funcs

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return
    ida_funcs.reanalyze_function(func)


def refresh_after_function_type_change(func_ea: int) -> dict[str, Any]:
    import ida_auto
    import ida_funcs
    import idautils

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return {"reanalyzed_functions": [], "decompiler_invalidated": []}

    refresh_function_analysis(func.start_ea)
    ida_auto.reanalyze_callers(func.start_ea, False)

    reanalyzed = {hex(func.start_ea)}
    invalidated: set[str] = set()

    if invalidate_decompilation(func.start_ea):
        invalidated.add(hex(func.start_ea))

    for ref in idautils.CodeRefsTo(func.start_ea, 1):
        caller = ida_funcs.get_func(ref)
        if caller is None:
            continue
        refresh_function_analysis(caller.start_ea)
        reanalyzed.add(hex(caller.start_ea))
        if invalidate_decompilation(caller.start_ea):
            invalidated.add(hex(caller.start_ea))

    return {
        "reanalyzed_functions": sorted(reanalyzed),
        "decompiler_invalidated": sorted(invalidated),
    }


def refresh_after_data_type_change(ea: int) -> dict[str, Any]:
    import ida_funcs
    import idautils

    affected: set[int] = set()
    func_start = _function_start(ea)
    if func_start is not None:
        affected.add(func_start)

    for xref in idautils.XrefsTo(ea, 0):
        caller_start = _function_start(xref.frm)
        if caller_start is not None:
            affected.add(caller_start)

    reanalyzed: list[str] = []
    invalidated: list[str] = []
    for func_ea in sorted(affected):
        refresh_function_analysis(func_ea)
        reanalyzed.append(hex(func_ea))
        if invalidate_decompilation(func_ea):
            invalidated.append(hex(func_ea))

    return {
        "reanalyzed_functions": reanalyzed,
        "decompiler_invalidated": invalidated,
    }


def refresh_after_local_variable_change(func_ea: int) -> dict[str, Any]:
    refresh_function_analysis(func_ea)
    invalidated = invalidate_decompilation(func_ea)
    return {
        "reanalyzed_functions": [hex(func_ea)] if _function_start(func_ea) is not None else [],
        "decompiler_invalidated": [hex(func_ea)] if invalidated else [],
    }
