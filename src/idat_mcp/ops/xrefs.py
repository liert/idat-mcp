from __future__ import annotations

from typing import Any

from idat_mcp.ops.common import resolve_ea, xref_type_name


def get_xrefs_to(address: str, limit: int = 100) -> dict[str, Any]:
    import idautils

    ea = resolve_ea(address)
    xrefs: list[dict[str, str]] = []
    for xref in idautils.XrefsTo(ea, 0):
        if len(xrefs) >= limit:
            break
        xrefs.append({"from": hex(xref.frm), "type": xref_type_name(xref.type)})

    return {"to": hex(ea), "count": len(xrefs), "xrefs": xrefs}


def get_xrefs_from(address: str, limit: int = 100) -> dict[str, Any]:
    import idautils

    ea = resolve_ea(address)
    xrefs: list[dict[str, str]] = []
    for xref in idautils.XrefsFrom(ea, 0):
        if len(xrefs) >= limit:
            break
        xrefs.append({"to": hex(xref.to), "type": xref_type_name(xref.type)})

    return {"from": hex(ea), "count": len(xrefs), "xrefs": xrefs}


OPERATIONS = {
    "get_xrefs_to": get_xrefs_to,
    "get_xrefs_from": get_xrefs_from,
}
