from __future__ import annotations

from typing import Any


def parse_address(value: str) -> int:
    value = value.strip()
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    if all(c in "0123456789abcdefABCDEF" for c in value) and any(c in "abcdefABCDEF" for c in value):
        return int(value, 16)
    return int(value)


def parse_size(value: str | int) -> int:
    if isinstance(value, bool):
        raise ValueError("size must be an integer or numeric string")
    if isinstance(value, int):
        return max(1, value)
    text = str(value).strip()
    if not text:
        raise ValueError("size must not be empty")
    return max(1, parse_address(text))


def resolve_ea(name_or_address: str) -> int:
    import ida_funcs
    import ida_idaapi
    import ida_name
    import idautils

    value = name_or_address.strip()
    if value.startswith("0x") or value.startswith("0X") or value.isdigit():
        return parse_address(value)

    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, value)
    if ea != ida_idaapi.BADADDR:
        return ea

    for func_ea in idautils.Functions():
        if ida_funcs.get_func_name(func_ea) == value:
            return func_ea

    for name_ea, name in idautils.Names():
        if name == value:
            return name_ea

    raise ValueError(f"Unknown name or address: {name_or_address!r}")


def is_user_function(func_ea: int) -> bool:
    import ida_funcs
    import ida_segment

    func = ida_funcs.get_func(func_ea)
    if func is None:
        return False

    if func.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK):
        return False

    if ida_segment.is_spec_ea(func_ea):
        return False

    seg = ida_segment.getseg(func_ea)
    if seg is None:
        return False

    seg_name = ida_segment.get_segm_name(seg) or ""
    if seg_name in (".plt", ".plt.got", "extern"):
        return False

    return True


def count_functions(include_imports: bool) -> int:
    import idautils

    if include_imports:
        return sum(1 for _ in idautils.Functions())
    return sum(1 for ea in idautils.Functions() if is_user_function(ea))


def resolve_function(name_or_address: str) -> Any:
    import ida_funcs

    ea = resolve_ea(name_or_address)
    func = ida_funcs.get_func(ea)
    if func is None:
        raise ValueError(f"No function at {name_or_address!r}")
    return func


def xref_type_name(xref_type: int) -> str:
    import ida_xref

    code_names = {
        ida_xref.fl_U: "unknown",
        ida_xref.fl_CF: "call_far",
        ida_xref.fl_CN: "call_near",
        ida_xref.fl_F: "flow",
        ida_xref.fl_JF: "jump_far",
        ida_xref.fl_JN: "jump_near",
    }
    data_names = {
        ida_xref.dr_U: "unknown",
        ida_xref.dr_O: "offset",
        ida_xref.dr_W: "write",
        ida_xref.dr_R: "read",
        ida_xref.dr_T: "text",
        ida_xref.dr_I: "informational",
        ida_xref.dr_S: "symbol",
    }
    if xref_type in code_names:
        return code_names[xref_type]
    if xref_type in data_names:
        return data_names[xref_type]
    return str(xref_type)
