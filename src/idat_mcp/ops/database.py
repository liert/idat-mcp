from __future__ import annotations

from pathlib import Path
from typing import Any

from idat_mcp.ops.common import count_functions


def _ensure_user_functions_analyzed() -> dict[str, Any]:
    import ida_auto
    import ida_ida
    import idautils

    user_count = count_functions(include_imports=False)
    if user_count > 0:
        return {
            "reanalyzed": False,
            "user_functions": user_count,
            "import_functions": count_functions(include_imports=True) - user_count,
        }

    total = sum(1 for _ in idautils.Functions())
    if total == 0 or total > user_count:
        ida_auto.plan_and_wait(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea(), True)

    user_count = count_functions(include_imports=False)
    import_count = count_functions(include_imports=True) - user_count
    return {
        "reanalyzed": True,
        "user_functions": user_count,
        "import_functions": import_count,
    }


def analyze_database() -> dict[str, Any]:
    import ida_auto
    import ida_ida

    ida_auto.plan_and_wait(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea(), True)
    user_count = count_functions(include_imports=False)
    import_count = count_functions(include_imports=True) - user_count
    return {
        "status": "analyzed",
        "user_functions": user_count,
        "import_functions": import_count,
    }


def open_database(path: str, recreate: bool = False) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()
    if not file_path.is_file():
        raise FileNotFoundError(f"Binary not found: {file_path}")

    import ida_auto
    import idapro

    ida_args = "-c" if recreate else None
    result = idapro.open_database(str(file_path), True, ida_args)
    if result != 0:
        raise RuntimeError(f"idapro.open_database failed with code {result}")

    ida_auto.auto_wait()
    analysis = _ensure_user_functions_analyzed()

    response = {
        "path": str(file_path),
        "auto_analysis": True,
        "recreate": recreate,
        "status": "open",
    }
    response.update(analysis)
    return response


def close_database(save: bool = True) -> dict[str, Any]:
    import idapro

    idapro.close_database(save)
    return {"status": "closed", "saved": save}


def get_database_info(database_path: str) -> dict[str, Any]:
    import ida_ida
    import ida_loader
    import ida_segment

    info = {
        "path": database_path,
        "processor": ida_ida.inf_get_procname(),
        "bitness": ida_ida.inf_get_app_bitness(),
        "min_ea": hex(ida_ida.inf_get_min_ea()),
        "max_ea": hex(ida_ida.inf_get_max_ea()),
        "file_type": ida_loader.get_file_type_name(),
        "segments": [],
    }

    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        info["segments"].append(
            {
                "name": ida_segment.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "permissions": seg.perm,
            }
        )
    return info


def list_segments() -> dict[str, Any]:
    import ida_segment

    segments: list[dict[str, Any]] = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        segments.append(
            {
                "name": ida_segment.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": hex(seg.end_ea - seg.start_ea),
                "permissions": seg.perm,
                "bitness": seg.bitness,
                "class": ida_segment.get_segm_class(seg),
            }
        )

    return {"count": len(segments), "segments": segments}


OPERATIONS = {
    "analyze_database": analyze_database,
    "get_database_info": get_database_info,
    "list_segments": list_segments,
}
