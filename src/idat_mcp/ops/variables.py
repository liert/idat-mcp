from __future__ import annotations

from typing import Any

from idat_mcp.ops.common import resolve_ea, resolve_function, xref_type_name


def _require_hexrays() -> None:
    import ida_hexrays

    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")


def _decompile_function(func_ea: int) -> Any:
    import ida_hexrays

    _require_hexrays()
    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc is None:
        raise RuntimeError(f"Decompilation failed for {hex(func_ea)}")
    return cfunc


def list_local_variables(function_address: str) -> dict[str, Any]:
    import ida_funcs
    import ida_name

    func = resolve_function(function_address)
    cfunc = _decompile_function(func.start_ea)
    variables: list[dict[str, Any]] = []

    for lv in cfunc.get_lvars():
        lv_type = lv.type()
        variables.append(
            {
                "name": lv.name,
                "type": lv_type.dstr() if lv_type and not lv_type.empty() else "",
                "is_argument": bool(lv.is_arg_var),
                "is_result": bool(lv.is_result_var),
                "width": lv.width,
            }
        )

    target_name = ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea) or ""
    return {
        "function": hex(func.start_ea),
        "name": target_name,
        "count": len(variables),
        "variables": variables,
    }


def get_local_variable_xrefs(
    function_address: str,
    variable_name: str,
    limit: int = 100,
) -> dict[str, Any]:
    import ida_hexrays

    func = resolve_function(function_address)
    cfunc = _decompile_function(func.start_ea)

    found = False
    for lv in cfunc.get_lvars():
        if lv.name == variable_name:
            found = True
            break
    if not found:
        raise ValueError(f"Local variable not found: {variable_name!r}")

    class _LvarXrefVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self, target_name: str, max_refs: int) -> None:
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            self.target_name = target_name
            self.max_refs = max_refs
            self.refs: list[dict[str, str]] = []

        def visit_expr(self, expr: Any) -> int:
            if len(self.refs) >= self.max_refs:
                return 1
            if expr.op == ida_hexrays.cot_var and expr.v.name == self.target_name:
                self.refs.append(
                    {
                        "address": hex(expr.ea),
                        "expression": expr.dstr(),
                    }
                )
            return 0

    visitor = _LvarXrefVisitor(variable_name, limit)
    visitor.apply_to(cfunc.body, None)

    return {
        "function": hex(func.start_ea),
        "variable": variable_name,
        "count": len(visitor.refs),
        "xrefs": visitor.refs,
    }


def get_global_variable_xrefs(name_or_address: str, limit: int = 100) -> dict[str, Any]:
    import ida_funcs
    import ida_name
    import idautils

    ea = resolve_ea(name_or_address)
    symbol_name = ida_name.get_name(ea) or name_or_address
    xrefs: list[dict[str, str]] = []

    for xref in idautils.XrefsTo(ea, 0):
        if len(xrefs) >= limit:
            break
        caller = ida_funcs.get_func(xref.frm)
        xrefs.append(
            {
                "from": hex(xref.frm),
                "type": xref_type_name(xref.type),
                "function": hex(caller.start_ea) if caller else "",
                "function_name": ida_funcs.get_func_name(caller.start_ea) if caller else "",
            }
        )

    return {
        "address": hex(ea),
        "name": symbol_name,
        "count": len(xrefs),
        "xrefs": xrefs,
    }


OPERATIONS = {
    "list_local_variables": list_local_variables,
    "get_local_variable_xrefs": get_local_variable_xrefs,
    "get_global_variable_xrefs": get_global_variable_xrefs,
}
