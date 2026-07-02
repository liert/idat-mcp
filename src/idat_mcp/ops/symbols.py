from __future__ import annotations

from typing import Any


def list_imports(limit: int = 500) -> dict[str, Any]:
    import ida_nalt

    imports: list[dict[str, Any]] = []
    for mod_index in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(mod_index) or f"module_{mod_index}"

        def _cb(ea, name, ordinal):
            if len(imports) >= limit:
                return False
            imports.append(
                {
                    "module": module,
                    "address": hex(ea),
                    "name": name or "",
                    "ordinal": ordinal,
                }
            )
            return True

        ida_nalt.enum_import_names(mod_index, _cb)
        if len(imports) >= limit:
            break

    return {"count": len(imports), "imports": imports}


def list_exports(limit: int = 500) -> dict[str, Any]:
    import idautils

    exports: list[dict[str, Any]] = []
    for _idx, ordinal, ea, name in idautils.Entries():
        if len(exports) >= limit:
            break
        exports.append(
            {
                "ordinal": ordinal,
                "address": hex(ea),
                "name": name or "",
            }
        )

    return {"count": len(exports), "exports": exports}


def list_global_names(filter: str = "", limit: int = 200) -> dict[str, Any]:
    import idautils

    needle = filter.lower()
    names: list[dict[str, str]] = []
    for ea, name in idautils.Names():
        if needle and needle not in name.lower() and needle not in hex(ea).lower():
            continue
        if len(names) >= limit:
            break
        names.append({"address": hex(ea), "name": name})

    return {"count": len(names), "names": names}


def demangle(name: str) -> dict[str, str]:
    import ida_name

    demangled = ida_name.demangle_name(name, ida_name.MNG_NODEFINIT)
    return {"name": name, "demangled": demangled or name}


OPERATIONS = {
    "list_imports": list_imports,
    "list_exports": list_exports,
    "list_global_names": list_global_names,
    "demangle": demangle,
}
