from __future__ import annotations

from typing import Any


def search_strings(min_length: int = 4, limit: int = 200) -> dict[str, Any]:
    import idautils

    strings: list[dict[str, str]] = []
    str_enum = idautils.Strings(default_setup=True)
    str_enum.setup(minlen=min_length)

    for item in str_enum:
        if item is None:
            continue
        if len(strings) >= limit:
            break
        strings.append(
            {
                "address": hex(item.ea),
                "length": item.length,
                "value": str(item),
            }
        )

    return {"count": len(strings), "strings": strings}


def search_bytes(pattern: str, limit: int = 100) -> dict[str, Any]:
    import ida_bytes
    import ida_ida
    import ida_idaapi

    start = ida_ida.inf_get_min_ea()
    end = ida_ida.inf_get_max_ea()
    matches: list[dict[str, str]] = []
    ea = start

    while len(matches) < limit:
        found = ida_bytes.find_bytes(pattern, ea, range_end=end)
        if found == ida_idaapi.BADADDR:
            break
        matches.append({"address": hex(found), "pattern": pattern})
        ea = found + 1

    return {"pattern": pattern, "count": len(matches), "matches": matches}


def search_immediate(value: int, limit: int = 100) -> dict[str, Any]:
    import ida_ida
    import ida_idaapi
    import ida_search

    ea = ida_ida.inf_get_min_ea()
    matches: list[dict[str, Any]] = []

    while len(matches) < limit:
        result = ida_search.find_imm(ea, ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT, value)
        if not result:
            break
        hit_ea, op_index = result
        if hit_ea == ida_idaapi.BADADDR:
            break
        matches.append({"address": hex(hit_ea), "operand_index": op_index, "value": hex(value)})
        ea = hit_ea

    return {"value": hex(value), "count": len(matches), "matches": matches}


OPERATIONS = {
    "search_strings": search_strings,
    "search_bytes": search_bytes,
    "search_immediate": search_immediate,
}
