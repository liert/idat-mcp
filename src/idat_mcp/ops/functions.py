from __future__ import annotations

from typing import Any

from idat_mcp.ops.common import is_user_function, parse_size, resolve_ea, resolve_function


def list_functions(
    offset: int = 0,
    limit: int = 100,
    filter: str = "",
    include_imports: bool = False,
) -> dict[str, Any]:
    import ida_funcs
    import ida_name
    import idautils

    functions: list[dict[str, str]] = []
    total = 0
    import_total = 0
    needle = filter.lower()

    for func_ea in idautils.Functions():
        is_user = is_user_function(func_ea)
        if not is_user:
            import_total += 1
        if not include_imports and not is_user:
            continue

        name = ida_funcs.get_func_name(func_ea) or ida_name.get_name(func_ea) or f"sub_{func_ea:X}"
        if needle and needle not in name.lower() and needle not in hex(func_ea).lower():
            continue
        total += 1
        if total <= offset:
            continue
        if len(functions) >= limit:
            continue
        functions.append(
            {"address": hex(func_ea), "name": name, "size": hex(ida_funcs.get_func(func_ea).size())}
        )

    result = {
        "total_matched": total,
        "offset": offset,
        "limit": limit,
        "include_imports": include_imports,
        "import_functions": import_total,
        "functions": functions,
    }
    if total == 0 and not include_imports and import_total > 0:
        result["hint"] = (
            "Only import stubs were found. Call ida_analyze_database or reopen with "
            "ida_open_database(recreate=True) to rebuild analysis."
        )
    elif total == 0 and import_total == 0:
        result["hint"] = "No functions found. Ensure auto-analysis completed via ida_open_database."
    return result


def get_function(name_or_address: str) -> dict[str, Any]:
    import ida_funcs
    import ida_name

    func = resolve_function(name_or_address)
    return {
        "address": hex(func.start_ea),
        "end": hex(func.end_ea),
        "name": ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea),
        "size": hex(func.size()),
        "flags": func.flags,
    }


def decompile_function(address: str) -> dict[str, str]:
    import ida_funcs
    import ida_hexrays
    import ida_name

    func = resolve_function(address)
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")

    cfunc = ida_hexrays.decompile(func.start_ea)
    if cfunc is None:
        raise RuntimeError(f"Decompilation failed for {address}")

    name = ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea)
    return {
        "address": hex(func.start_ea),
        "name": name or "",
        "pseudocode": str(cfunc),
    }


def disassemble(address: str, size: str | int = 128) -> dict[str, Any]:
    import ida_bytes
    import ida_lines
    import ida_ua

    ea = resolve_ea(address)
    byte_limit = min(parse_size(size), 4096)
    end_ea = ea + byte_limit
    instructions: list[dict[str, str]] = []
    current = ea

    while current < end_ea:
        if not ida_bytes.is_loaded(current):
            break
        insn = ida_ua.insn_t()
        insn_size = ida_ua.decode_insn(insn, current)
        if insn_size <= 0:
            break
        line = ida_lines.generate_disasm_line(
            current,
            ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS,
        )
        instructions.append(
            {
                "address": hex(current),
                "bytes": ida_bytes.get_bytes(current, insn_size).hex(),
                "text": line or "?",
            }
        )
        current += insn_size

    return {
        "start": hex(ea),
        "size": hex(byte_limit),
        "bytes_disassembled": hex(current - ea),
        "instruction_count": len(instructions),
        "instructions": instructions,
    }


def get_bytes(address: str, size: int = 64) -> dict[str, str]:
    import ida_bytes

    ea = resolve_ea(address)
    size = max(1, min(size, 4096))
    if not ida_bytes.is_loaded(ea):
        raise ValueError(f"Address {address!r} is not mapped")
    data = ida_bytes.get_bytes(ea, size)
    return {"address": hex(ea), "size": size, "hex": data.hex()}


def get_function_callers(name_or_address: str, limit: int = 100) -> dict[str, Any]:
    import ida_funcs
    import ida_name
    import idautils

    func = resolve_function(name_or_address)
    callers: list[dict[str, str]] = []
    for ref in idautils.CodeRefsTo(func.start_ea, 1):
        if len(callers) >= limit:
            break
        caller_func = ida_funcs.get_func(ref)
        callers.append(
            {
                "from": hex(ref),
                "caller_function": hex(caller_func.start_ea) if caller_func else "",
                "caller_name": (
                    ida_funcs.get_func_name(caller_func.start_ea)
                    if caller_func
                    else ida_name.get_name(ref) or ""
                ),
            }
        )

    target_name = ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea) or ""
    return {
        "function": hex(func.start_ea),
        "name": target_name,
        "count": len(callers),
        "callers": callers,
    }


def get_function_callees(name_or_address: str, limit: int = 100) -> dict[str, Any]:
    import ida_funcs
    import ida_name
    import idautils
    import idc

    func = resolve_function(name_or_address)
    callees: list[dict[str, str]] = []
    seen: set[int] = set()

    for head in idautils.FuncItems(func.start_ea):
        if len(callees) >= limit:
            break
        for ref in idautils.XrefsFrom(head):
            if ref.type not in (idc.fl_CN, idc.fl_CF):
                continue
            target_ea = ref.to
            if target_ea in seen:
                continue
            seen.add(target_ea)
            callee_func = ida_funcs.get_func(target_ea)
            callees.append(
                {
                    "call_site": hex(head),
                    "instruction": idc.print_insn_mnem(head),
                    "target": hex(target_ea),
                    "target_name": ida_funcs.get_func_name(target_ea) or ida_name.get_name(target_ea) or "",
                    "target_function": hex(callee_func.start_ea) if callee_func else "",
                }
            )

    target_name = ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea) or ""
    return {
        "function": hex(func.start_ea),
        "name": target_name,
        "count": len(callees),
        "callees": callees,
    }


def get_function_cfg(name_or_address: str) -> dict[str, Any]:
    import ida_funcs
    import ida_gdl
    import ida_name

    func = resolve_function(name_or_address)
    flow = ida_gdl.FlowChart(func)
    blocks: list[dict[str, Any]] = []
    for block in flow:
        succ = [hex(s.start_ea) for s in block.succs()]
        blocks.append(
            {
                "id": block.id,
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": hex(block.end_ea - block.start_ea),
                "successors": succ,
            }
        )

    target_name = ida_funcs.get_func_name(func.start_ea) or ida_name.get_name(func.start_ea) or ""
    return {
        "function": hex(func.start_ea),
        "name": target_name,
        "block_count": len(blocks),
        "blocks": blocks,
    }


OPERATIONS = {
    "list_functions": list_functions,
    "get_function": get_function,
    "decompile_function": decompile_function,
    "disassemble": disassemble,
    "get_bytes": get_bytes,
    "get_function_callers": get_function_callers,
    "get_function_callees": get_function_callees,
    "get_function_cfg": get_function_cfg,
}
