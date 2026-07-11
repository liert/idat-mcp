#!/usr/bin/env python3
"""Install idat-mcp as a systemd service.

This is intentionally a service installer, not the Python package build file;
package metadata lives in pyproject.toml.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8745
DEFAULT_SERVICE_NAME = "idat-mcp"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install idat-mcp as a systemd service")
    parser.add_argument(
        "--ida-dir",
        default=os.environ.get("IDADIR"),
        help="IDA Pro installation directory (default: $IDADIR)",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"HTTP bind address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"HTTP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--service-name",
        default=DEFAULT_SERVICE_NAME,
        help=f"systemd service name (default: {DEFAULT_SERVICE_NAME})",
    )
    parser.add_argument(
        "--user",
        action="store_true",
        help="Install a per-user service instead of a system service",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Install and enable the service without starting it now",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the unit file and destination without changing the system",
    )
    parser.add_argument(
        "--force-reinstall",
        action="store_true",
        help="Reinstall Python packages and reactivate idalib",
    )
    return parser


def systemd_quote(value: str | Path) -> str:
    value = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{value}"'


def systemd_path(value: str | Path) -> str:
    """Escape a path for directives that do not accept shell-style quotes."""
    safe = b"/._-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(
        chr(byte) if byte in safe else f"\\x{byte:02x}" for byte in os.fsencode(value)
    )


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> Path:
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or newer is required")
    if not args.ida_dir:
        parser.error("--ida-dir is required when IDADIR is not set")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    valid_service_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@_.-"
    if not args.service_name or any(c not in valid_service_chars for c in args.service_name):
        parser.error("--service-name contains invalid characters")

    ida_dir = Path(args.ida_dir).expanduser().resolve()
    for path, label in (
        (ida_dir, "IDA directory"),
        (ida_dir / "idat", "idat executable"),
        (ida_dir / "libidalib.so", "libidalib.so"),
        (ida_dir / "idalib/python/py-activate-idalib.py", "idalib activation script"),
    ):
        exists = path.is_dir() if path == ida_dir else path.is_file()
        if not exists:
            parser.error(f"{label} not found: {path}")
    return ida_dir


def unit_path(service_name: str, user_service: bool) -> Path:
    if user_service:
        return Path.home() / ".config/systemd/user" / f"{service_name}.service"
    return Path("/etc/systemd/system") / f"{service_name}.service"


def render_unit(ida_dir: Path, host: str, port: int, user_service: bool) -> str:
    executable = ROOT / ".venv/bin/python"
    server = ROOT / "server.py"
    install_target = "default.target" if user_service else "multi-user.target"
    return f"""[Unit]
Description=Headless IDA Pro MCP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={systemd_path(ROOT)}
Environment={systemd_quote(f"IDADIR={ida_dir}")}
ExecStart={systemd_quote(executable)} {systemd_quote(server)} --ida-dir {systemd_quote(ida_dir)} --host {systemd_quote(host)} --port {port}
Restart=on-failure
RestartSec=3

[Install]
WantedBy={install_target}
"""


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def file_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_install_state(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_install_state(path: Path, state: dict[str, str]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def install_python_environment(ida_dir: Path, force: bool = False) -> None:
    venv_python = ROOT / ".venv/bin/python"
    if not venv_python.exists():
        run([sys.executable, "-m", "venv", str(ROOT / ".venv")])

    wheels = sorted((ida_dir / "idalib/python").glob("idapro-*.whl"))
    if not wheels:
        raise FileNotFoundError(f"idalib Python wheel not found in {ida_dir / 'idalib/python'}")
    wheel = wheels[-1]
    state_path = ROOT / ".venv/.idat-mcp-setup.json"
    state = {} if force else load_install_state(state_path)
    project_fingerprint = file_fingerprint(ROOT / "pyproject.toml")
    wheel_fingerprint = file_fingerprint(wheel)

    if state.get("project") != project_fingerprint:
        run([str(venv_python), "-m", "pip", "install", "-U", "pip"])
        run([str(venv_python), "-m", "pip", "install", "-e", str(ROOT)])
        state["project"] = project_fingerprint
        save_install_state(state_path, state)
    else:
        print("Python project and dependencies are already installed; skipping.")

    if state.get("idalib_wheel") != wheel_fingerprint:
        run([str(venv_python), "-m", "pip", "install", str(wheel)])
        state["idalib_wheel"] = wheel_fingerprint
        state.pop("activated_ida_dir", None)
        save_install_state(state_path, state)
    else:
        print("idalib Python package is already installed; skipping.")

    ida_key = str(ida_dir)
    if state.get("activated_ida_dir") != ida_key:
        run(
            [
                str(venv_python),
                str(ida_dir / "idalib/python/py-activate-idalib.py"),
                "-d",
                ida_key,
            ]
        )
        state["activated_ida_dir"] = ida_key
        save_install_state(state_path, state)
    else:
        print(f"idalib is already activated for {ida_dir}; skipping.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ida_dir = validate_args(args, parser)
    destination = unit_path(args.service_name, args.user)
    unit = render_unit(ida_dir, args.host, args.port, args.user)

    if args.dry_run:
        print(f"Would write: {destination}\n")
        print(unit, end="")
        return 0

    if not args.user and os.geteuid() != 0:
        parser.error("system service installation requires root; use sudo or pass --user")

    install_python_environment(ida_dir, force=args.force_reinstall)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(unit, encoding="utf-8")

    systemctl = ["systemctl"] + (["--user"] if args.user else [])
    verify = ["systemd-analyze"] + (["--user"] if args.user else [])
    run([*verify, "verify", str(destination)])
    run([*systemctl, "daemon-reload"])
    service = f"{args.service_name}.service"
    run([*systemctl, "enable", service])
    if not args.no_start:
        run([*systemctl, "restart", service])
        run([*systemctl, "is-active", "--quiet", service])

    print(f"Installed {args.service_name}.service")
    print(f"MCP endpoint: http://{args.host}:{args.port}/mcp")
    print(f"Status: {' '.join(systemctl)} status {args.service_name}.service")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
