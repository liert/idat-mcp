from __future__ import annotations

from typing import Any

from idat_mcp.ops.common import parse_address, parse_size, resolve_ea, resolve_function
from idat_mcp.ops.refresh import (
    refresh_after_data_type_change,
    refresh_after_function_type_change,
    refresh_after_local_variable_change,
)


def _type_to_string(tif: Any) -> str:
    return tif.dstr() if tif and not tif.empty() else ""


def _resolve_struct_id(name: str) -> int:
    import ida_idaapi
    import ida_typeinf
    import idc

    tid = ida_typeinf.get_named_type_tid(name)
    if tid != ida_idaapi.BADADDR:
        return tid

    sid = idc.get_struc_id(name)
    if sid != idc.BADADDR:
        return sid

    raise ValueError(f"Structure not found: {name!r}")


def _member_type_to_idc(member_type: str) -> tuple[int, int, int]:
    import ida_typeinf
    import idc

    tif = ida_typeinf.tinfo_t()
    remainder = ida_typeinf.parse_decl(tif, None, f"{member_type} __member__;", ida_typeinf.PT_SIL)
    if remainder is not None:
        raise ValueError(f"Failed to parse member type {member_type!r}: {remainder}")

    size = tif.get_size()
    if size <= 0:
        raise ValueError(f"Could not determine size for member type {member_type!r}")

    if tif.is_ptr():
        flag = idc.FF_QWORD if size == 8 else idc.FF_DWORD
    elif tif.is_array():
        flag = idc.FF_BYTE
    elif size == 1:
        flag = idc.FF_BYTE
    elif size == 2:
        flag = idc.FF_WORD
    elif size == 4:
        flag = idc.FF_DWORD
    elif size == 8:
        flag = idc.FF_QWORD
    else:
        flag = idc.FF_BYTE

    return flag, size, -1


def list_structs(limit: int = 200) -> dict[str, Any]:
    import idautils

    structs: list[dict[str, Any]] = []
    for ordinal, sid, struct_name in idautils.Structs():
        if len(structs) >= limit:
            break
        structs.append({"ordinal": ordinal, "id": hex(sid), "name": struct_name})

    return {"count": len(structs), "structs": structs}


def get_struct_members(name: str) -> dict[str, Any]:
    import idautils

    sid = _resolve_struct_id(name)
    members: list[dict[str, Any]] = []
    for offset, member_name, size in idautils.StructMembers(sid):
        members.append(
            {
                "offset": hex(offset),
                "name": member_name,
                "size": size,
            }
        )

    return {"name": name, "id": hex(sid), "count": len(members), "members": members}


def get_type_at_address(address: str) -> dict[str, Any]:
    import ida_nalt
    import ida_typeinf

    ea = resolve_ea(address)
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        return {"address": hex(ea), "has_type": False, "type": ""}

    return {"address": hex(ea), "has_type": True, "type": _type_to_string(tif)}


def set_type_at_address(address: str, type_decl: str) -> dict[str, str]:
    import ida_typeinf

    ea = resolve_ea(address)
    if not ida_typeinf.apply_cdecl(None, ea, type_decl, ida_typeinf.TINFO_DEFINITE):
        raise RuntimeError(f"Failed to apply type {type_decl!r} at {hex(ea)}")

    response = {"address": hex(ea), "type": type_decl}
    response.update(refresh_after_data_type_change(ea))
    return response


def apply_function_type(address: str, prototype: str) -> dict[str, str]:
    import ida_typeinf

    func = resolve_function(address)
    if not ida_typeinf.apply_cdecl(None, func.start_ea, prototype, ida_typeinf.TINFO_DEFINITE):
        raise RuntimeError(f"Failed to apply type {prototype!r} at {hex(func.start_ea)}")

    response = {"address": hex(func.start_ea), "prototype": prototype}
    response.update(refresh_after_function_type_change(func.start_ea))
    return response


def create_struct(declaration: str) -> dict[str, Any]:
    import ida_typeinf

    ida_typeinf.begin_type_updating(ida_typeinf.UTP_STRUCT)
    try:
        count = ida_typeinf.parse_decls(None, declaration, None, ida_typeinf.PT_SIL | ida_typeinf.PT_TYP)
        if count <= 0:
            raise RuntimeError(f"Failed to parse struct declaration: {declaration!r}")
    finally:
        ida_typeinf.end_type_updating(ida_typeinf.UTP_STRUCT)

    return {"status": "created", "parsed_count": count, "declaration": declaration}


def add_struct_member(
    struct_name: str,
    member_name: str,
    member_type: str,
    offset: str | int | None = None,
) -> dict[str, Any]:
    import idc

    sid = _resolve_struct_id(struct_name)
    if offset is None:
        member_offset = idc.get_struc_size(sid)
    else:
        member_offset = parse_size(offset)

    flag, size, typeid = _member_type_to_idc(member_type)
    if idc.add_struc_member(sid, member_name, member_offset, flag, typeid, size) != 0:
        raise RuntimeError(
            f"Failed to add member {member_name!r} ({member_type}) to struct {struct_name!r}"
        )

    return {
        "struct": struct_name,
        "member": member_name,
        "member_type": member_type,
        "offset": hex(member_offset),
        "size": size,
    }


def apply_struct_at_address(address: str, struct_name: str) -> dict[str, str]:
    import ida_typeinf

    ea = resolve_ea(address)
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(struct_name):
        raise ValueError(f"Structure type not found: {struct_name!r}")

    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
        raise RuntimeError(f"Failed to apply struct {struct_name!r} at {hex(ea)}")

    response = {"address": hex(ea), "struct": struct_name, "type": _type_to_string(tif)}
    response.update(refresh_after_data_type_change(ea))
    return response


def rename_local_variable(function_address: str, old_name: str, new_name: str) -> dict[str, str]:
    import ida_funcs
    import ida_hexrays

    func = resolve_function(function_address)
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")

    if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
        raise RuntimeError(f"Failed to rename local variable {old_name!r} to {new_name!r}")

    response = {
        "function": hex(func.start_ea),
        "old_name": old_name,
        "new_name": new_name,
    }
    response.update(refresh_after_local_variable_change(func.start_ea))
    return response


def set_local_variable_type(function_address: str, variable_name: str, type_decl: str) -> dict[str, str]:
    import ida_hexrays
    import ida_typeinf

    func = resolve_function(function_address)
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays decompiler is not available")

    tif = ida_typeinf.tinfo_t()
    remainder = ida_typeinf.parse_decl(tif, None, f"{type_decl} __tmp__;", ida_typeinf.PT_SIL)
    if remainder is not None:
        raise ValueError(f"Failed to parse type {type_decl!r}: {remainder}")

    class _LvarTypeModifier(ida_hexrays.user_lvar_modifier_t):
        def __init__(self, target_name: str, new_type: Any) -> None:
            super().__init__()
            self.target_name = target_name
            self.new_type = new_type

        def modify_lvars(self, lvinf: Any) -> bool:
            for index in range(lvinf.size()):
                lsi = lvinf.at(index)
                if lsi.name == self.target_name:
                    lsi.type = self.new_type
                    return True
            return False

    if not ida_hexrays.modify_user_lvars(func.start_ea, _LvarTypeModifier(variable_name, tif)):
        raise RuntimeError(f"Failed to set type {type_decl!r} on variable {variable_name!r}")

    response = {
        "function": hex(func.start_ea),
        "variable": variable_name,
        "type": type_decl,
    }
    response.update(refresh_after_local_variable_change(func.start_ea))
    return response


OPERATIONS = {
    "list_structs": list_structs,
    "get_struct_members": get_struct_members,
    "get_type_at_address": get_type_at_address,
    "set_type_at_address": set_type_at_address,
    "apply_function_type": apply_function_type,
    "create_struct": create_struct,
    "add_struct_member": add_struct_member,
    "apply_struct_at_address": apply_struct_at_address,
    "rename_local_variable": rename_local_variable,
    "set_local_variable_type": set_local_variable_type,
}
