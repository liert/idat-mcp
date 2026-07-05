from __future__ import annotations

from collections import deque
from typing import Any

from idat_mcp.ops.common import resolve_ea, resolve_function


def _func_label(func_ea: int) -> dict[str, str]:
    import ida_funcs
    import ida_name

    return {
        "address": hex(func_ea),
        "name": ida_funcs.get_func_name(func_ea) or ida_name.get_name(func_ea) or "",
    }


def _collect_callee_func_starts(func_ea: int) -> set[int]:
    import ida_funcs
    import idautils
    import idc

    callees: set[int] = set()
    for head in idautils.FuncItems(func_ea):
        for ref in idautils.XrefsFrom(head):
            if ref.type not in (idc.fl_CN, idc.fl_CF):
                continue
            callee_func = ida_funcs.get_func(ref.to)
            if callee_func is not None:
                callees.add(callee_func.start_ea)
    return callees


def find_call_path(
    start_func: str,
    end_func: str,
    max_depth: int = 10,
    max_paths: int = 5,
) -> dict[str, Any]:
    import ida_funcs

    start_ea = resolve_function(start_func).start_ea
    end_ea = resolve_function(end_func).start_ea
    max_depth = max(1, min(max_depth, 64))
    max_paths = max(1, min(max_paths, 20))

    if start_ea == end_ea:
        chain = [_func_label(start_ea)]
        return {
            "start": hex(start_ea),
            "end": hex(end_ea),
            "found": True,
            "shortest_depth": 0,
            "path_count": 1,
            "paths": [{"depth": 0, "chain": chain}],
        }

    callee_cache: dict[int, set[int]] = {}

    def callees(func_ea: int) -> set[int]:
        if func_ea not in callee_cache:
            callee_cache[func_ea] = _collect_callee_func_starts(func_ea)
        return callee_cache[func_ea]

    # BFS for shortest path
    queue: deque[tuple[int, list[int]]] = deque([(start_ea, [start_ea])])
    visited_depth: dict[int, int] = {start_ea: 0}
    shortest_depth: int | None = None
    shortest_path: list[int] | None = None

    while queue:
        current, path = queue.popleft()
        depth = len(path) - 1
        if depth >= max_depth:
            continue
        if shortest_depth is not None and depth >= shortest_depth:
            continue

        for callee_ea in callees(current):
            if callee_ea in path:
                continue
            next_path = path + [callee_ea]
            next_depth = depth + 1

            if callee_ea == end_ea:
                if shortest_depth is None or next_depth < shortest_depth:
                    shortest_depth = next_depth
                    shortest_path = next_path
                continue

            prev = visited_depth.get(callee_ea)
            if prev is not None and prev <= next_depth:
                continue
            visited_depth[callee_ea] = next_depth
            queue.append((callee_ea, next_path))

    paths: list[dict[str, Any]] = []
    if shortest_path is not None:
        paths.append(
            {
                "depth": len(shortest_path) - 1,
                "chain": [_func_label(ea) for ea in shortest_path],
            }
        )

        # Collect a few alternate paths within max_depth using bounded DFS
        if max_paths > 1:

            def dfs(current: int, path: list[int], collected: list[list[int]]) -> None:
                if len(collected) >= max_paths:
                    return
                if current == end_ea:
                    if path != shortest_path:
                        collected.append(list(path))
                    return
                if len(path) - 1 >= max_depth:
                    return
                if shortest_depth is not None and len(path) - 1 >= shortest_depth:
                    return
                for callee_ea in callees(current):
                    if callee_ea in path:
                        continue
                    path.append(callee_ea)
                    dfs(callee_ea, path, collected)
                    path.pop()

            alternates: list[list[int]] = []
            dfs(start_ea, [start_ea], alternates)
            alternates.sort(key=len)
            for alt in alternates[: max_paths - 1]:
                paths.append(
                    {
                        "depth": len(alt) - 1,
                        "chain": [_func_label(ea) for ea in alt],
                    }
                )

    return {
        "start": hex(start_ea),
        "start_name": ida_funcs.get_func_name(start_ea) or "",
        "end": hex(end_ea),
        "end_name": ida_funcs.get_func_name(end_ea) or "",
        "found": bool(paths),
        "shortest_depth": shortest_depth,
        "max_depth": max_depth,
        "path_count": len(paths),
        "paths": paths,
    }


def _collect_var_indices(expr: Any) -> set[int]:
    import ida_hexrays

    indices: set[int] = set()

    class _VarCollector(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, subexpr: Any) -> int:
            if subexpr.op == ida_hexrays.cot_var:
                indices.add(subexpr.v.idx)
            return 0

    _VarCollector().apply_to(expr, None)
    return indices


def _statement_for_expr(expr: Any) -> Any:
    import ida_hexrays

    current = expr
    while current is not None:
        if current.op in (
            ida_hexrays.cot_asg,
            ida_hexrays.cot_call,
            ida_hexrays.cit_if,
            ida_hexrays.cit_for,
            ida_hexrays.cit_while,
            ida_hexrays.cit_return,
            ida_hexrays.cit_expr,
        ):
            return current
        current = getattr(current, "parent", None)
    return expr


def get_backward_slice(
    address: str,
    variable_name: str,
    limit: int = 100,
) -> dict[str, Any]:
    import ida_funcs
    import ida_hexrays
    import ida_name

    from idat_mcp.ops.variables import _decompile_function

    ea = resolve_ea(address)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise ValueError(f"No function at address {address!r}")

    cfunc = _decompile_function(func.start_ea)
    lvars = cfunc.get_lvars()
    target_idx = next((index for index, lv in enumerate(lvars) if lv.name == variable_name), None)
    if target_idx is None:
        raise ValueError(f"Local variable not found: {variable_name!r}")

    assignments: dict[int, list[Any]] = {}
    all_exprs: list[Any] = []

    class _SliceCollector(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_expr(self, expr: Any) -> int:
            all_exprs.append(expr)
            if expr.op == ida_hexrays.cot_asg:
                lhs = expr.x
                if lhs.op == ida_hexrays.cot_var:
                    assignments.setdefault(lhs.v.idx, []).append(expr)
            return 0

    _SliceCollector().apply_to(cfunc.body, None)

    seed_expr: Any | None = None
    for expr in all_exprs:
        if expr.op != ida_hexrays.cot_var or expr.v.idx != target_idx:
            continue
        if expr.ea == ea:
            seed_expr = expr
            break
    if seed_expr is None:
        for expr in all_exprs:
            if expr.op != ida_hexrays.cot_var or expr.v.idx != target_idx:
                continue
            if expr.ea <= ea:
                seed_expr = expr
            if expr.ea > ea and seed_expr is not None:
                break
    if seed_expr is None:
        raise ValueError(
            f"No use of variable {variable_name!r} found at or before {hex(ea)} in decompiled code"
        )

    sliced_vars: set[int] = {target_idx}
    changed = True
    while changed:
        changed = False
        for var_idx in list(sliced_vars):
            for assign_expr in assignments.get(var_idx, []):
                for dep_idx in _collect_var_indices(assign_expr.y):
                    if dep_idx not in sliced_vars:
                        sliced_vars.add(dep_idx)
                        changed = True

    sink_stmt: Any | None = None
    for expr in all_exprs:
        if expr.ea != ea:
            continue
        if expr.op in (
            ida_hexrays.cot_asg,
            ida_hexrays.cot_call,
        ):
            sink_stmt = expr
            break
    if sink_stmt is None:
        sink_stmt = _statement_for_expr(seed_expr)
    slice_entries: list[dict[str, str]] = []
    seen_ea: set[int] = set()

    def add_entry(stmt: Any, kind: str) -> None:
        if len(slice_entries) >= limit:
            return
        import ida_idaapi

        stmt_ea = stmt.ea if getattr(stmt, "ea", ida_idaapi.BADADDR) != ida_idaapi.BADADDR else ea
        if stmt_ea in seen_ea:
            return
        seen_ea.add(stmt_ea)
        slice_entries.append(
            {
                "address": hex(stmt_ea),
                "expression": stmt.dstr(),
                "kind": kind,
            }
        )

    add_entry(sink_stmt, "sink")
    for var_idx in sliced_vars:
        for assign_expr in assignments.get(var_idx, []):
            add_entry(assign_expr, "def")
            if len(slice_entries) >= limit:
                break
        if len(slice_entries) >= limit:
            break

    slice_entries.sort(key=lambda item: int(item["address"], 16), reverse=True)
    func_name = ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea) or ""

    return {
        "address": hex(ea),
        "variable": variable_name,
        "function": hex(func.start_ea),
        "function_name": func_name,
        "seed_expression": seed_expr.dstr(),
        "sliced_variables": [
            lvars[index].name for index in sorted(sliced_vars) if index < len(lvars)
        ],
        "count": len(slice_entries),
        "slice": slice_entries,
    }


def _normalize_reg(name: str) -> str:
    return name.strip().upper().replace(" ", "")


def _dest_register(head: int, mnem: str) -> str | None:
    import idc

    if mnem in {"mov", "movz", "movk", "movw", "movn", "adr", "adrp", "ldr", "add", "sub", "ldp"}:
        op0 = idc.print_operand(head, 0)
        return _normalize_reg(op0.split(",")[0])
    return None


def _resolve_memory_ea(head: int, op_index: int) -> int | None:
    import ida_idaapi
    import ida_bytes
    import ida_idaapi
    import idc

    op_type = idc.get_operand_type(head, op_index)
    if op_type in (idc.o_mem, idc.o_far, idc.o_near):
        value = idc.get_operand_value(head, op_index)
        return value if value not in (idc.BADADDR, ida_idaapi.BADADDR) else None
    if op_type in (idc.o_displ, idc.o_phrase):
        value = idc.get_operand_value(head, op_index)
        if value in (idc.BADADDR, ida_idaapi.BADADDR):
            return None
        if ida_bytes.is_mapped(value):
            return value
    return None


def _trace_register_targets(
    reg: str,
    before_ea: int,
    func_start: int,
    max_insns: int = 64,
) -> list[int]:
    import ida_idaapi
    import idautils
    import idc

    reg = _normalize_reg(reg)
    items = list(idautils.FuncItems(func_start))
    try:
        start_index = next(index for index, head in enumerate(items) if head >= before_ea)
    except StopIteration:
        start_index = len(items)

    targets: list[int] = []
    scanned = 0
    pending_reg = reg

    for head in reversed(items[:start_index]):
        if scanned >= max_insns:
            break
        scanned += 1
        mnem = idc.print_insn_mnem(head).lower()
        dest = _dest_register(head, mnem)
        if dest != pending_reg:
            continue

        if mnem in {"mov", "movz", "movw", "movn", "adr", "adrp"}:
            value = idc.get_operand_value(head, 1)
            if value not in (idc.BADADDR, ida_idaapi.BADADDR):
                targets.append(value)
            continue

        if mnem == "movk":
            value = idc.get_operand_value(head, 1)
            if value not in (idc.BADADDR, ida_idaapi.BADADDR):
                targets.append(value)
            continue

        if mnem == "add":
            value = idc.get_operand_value(head, 2)
            if value not in (idc.BADADDR, ida_idaapi.BADADDR):
                targets.append(value)
            continue

        if mnem in {"ldr", "ldp"}:
            mem_ea = _resolve_memory_ea(head, 1 if mnem == "ldr" else 2)
            if mem_ea is not None:
                targets.append(mem_ea)
            base = idc.print_operand(head, 1 if mnem == "ldr" else 2)
            for token in base.replace("[", " ").replace("]", " ").split(","):
                token = token.strip()
                if token and token.upper().startswith(("X", "W", "R")):
                    nested = _trace_register_targets(token, head, func_start, max_insns=16)
                    targets.extend(nested)
            continue

        if mnem == "sub":
            nested_reg = _normalize_reg(idc.print_operand(head, 1))
            nested = _trace_register_targets(nested_reg, head, func_start, max_insns=16)
            targets.extend(nested)

    return targets


def _is_indirect_call_insn(head: int) -> bool:
    import ida_funcs
    import idautils
    import idc

    mnem = idc.print_insn_mnem(head).lower()
    call_mnems = {
        "call",
        "bl",
        "blr",
        "br",
        "jal",
        "jalr",
        "jsr",
        "jmp",
    }
    if mnem not in call_mnems:
        return False

    for ref in idautils.XrefsFrom(head):
        if ref.type not in (idc.fl_CN, idc.fl_CF):
            continue
        if ida_funcs.get_func(ref.to) is not None:
            return False

    op_type = idc.get_operand_type(head, 0)
    if op_type in (idc.o_reg, idc.o_displ, idc.o_phrase, idc.o_mem):
        return True

    return mnem in {"blr", "br", "jalr", "jmp"}


def _resolve_indirect_call_targets(head: int, func_start: int) -> list[int]:
    import ida_bytes
    import ida_funcs
    import ida_idaapi
    import ida_nalt
    import idc

    candidates: list[int] = []
    op_type = idc.get_operand_type(head, 0)

    if op_type == idc.o_reg:
        reg = idc.print_operand(head, 0)
        candidates.extend(_trace_register_targets(reg, head, func_start))
    elif op_type in (idc.o_mem, idc.o_displ, idc.o_phrase, idc.o_far, idc.o_near):
        mem_ea = _resolve_memory_ea(head, 0)
        if mem_ea is not None:
            candidates.append(mem_ea)

    resolved: list[int] = []
    seen: set[int] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)

        target_ea = candidate
        if ida_bytes.is_mapped(candidate) and not ida_funcs.get_func(candidate):
            import ida_ida
            ptr_size = 8 if ida_ida.inf_is_64bit() else 4
            if ptr_size == 8 and ida_bytes.is_mapped(candidate + 7):
                target_ea = ida_bytes.get_qword(candidate)
            elif ptr_size == 4 and ida_bytes.is_mapped(candidate + 3):
                target_ea = ida_bytes.get_dword(candidate)

        if target_ea in (idc.BADADDR, ida_idaapi.BADADDR):
            continue
        if ida_funcs.get_func(target_ea) is not None or ida_bytes.is_mapped(target_ea):
            resolved.append(target_ea)

    return resolved


def resolve_indirect_calls(
    function_address: str,
    add_xrefs: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    import ida_funcs
    import ida_name
    import ida_xref
    import idautils
    import idc

    func = resolve_function(function_address)
    results: list[dict[str, Any]] = []

    for head in idautils.FuncItems(func.start_ea):
        if len(results) >= limit:
            break
        if not _is_indirect_call_insn(head):
            continue

        targets = _resolve_indirect_call_targets(head, func.start_ea)
        target_entries: list[dict[str, str]] = []
        xrefs_added = 0

        for target_ea in targets:
            target_func = ida_funcs.get_func(target_ea)
            entry = {
                "target": hex(target_ea),
                "target_name": ida_funcs.get_func_name(target_ea) or ida_name.get_name(target_ea) or "",
                "target_function": hex(target_func.start_ea) if target_func else "",
            }
            target_entries.append(entry)

            if add_xrefs and target_func is not None:
                if ida_xref.add_cref(head, target_func.start_ea, ida_xref.fl_CN):
                    xrefs_added += 1

        results.append(
            {
                "call_site": hex(head),
                "instruction": idc.print_insn_mnem(head),
                "operand": idc.print_operand(head, 0),
                "resolved_count": len(target_entries),
                "targets": target_entries,
                "xrefs_added": xrefs_added,
            }
        )

    func_name = ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea) or ""
    return {
        "function": hex(func.start_ea),
        "name": func_name,
        "count": len(results),
        "add_xrefs": add_xrefs,
        "indirect_calls": results,
    }


OPERATIONS = {
    "find_call_path": find_call_path,
    "get_backward_slice": get_backward_slice,
    "resolve_indirect_calls": resolve_indirect_calls,
}
