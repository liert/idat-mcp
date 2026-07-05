from __future__ import annotations

import argparse
import sys

from idat_mcp.config import Settings
from idat_mcp.pool import shutdown_pool
from idat_mcp.server import create_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Headless IDA Pro MCP server over HTTP (powered by idalib/idat)",
    )
    parser.add_argument(
        "--ida-dir",
        "-d",
        required=True,
        help="IDA Pro installation directory (must contain idat and libidalib.so)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8745,
        help="HTTP port (default: 8745)",
    )
    parser.add_argument(
        "--stateless",
        action="store_true",
        help="Use stateless HTTP mode (no mcp-session-id; for some remote clients)",
    )
    parser.add_argument(
        "--allowed-hosts",
        default="",
        help="Comma-separated Host allowlist for remote access (e.g. 172.29.64.1:*,localhost:8745)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=None,
        help="Maximum number of concurrently open databases",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Log MCP tool invocations and elapsed time to stderr",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    allowed_hosts = [h.strip() for h in args.allowed_hosts.split(",") if h.strip()]

    settings = Settings.from_cli(
        ida_dir=args.ida_dir,
        host=args.host,
        port=args.port,
        max_workers=args.max_workers,
        stateless_http=args.stateless,
        allowed_hosts=allowed_hosts,
        debug=args.debug,
    )

    try:
        settings.validate()
        settings.apply()
    except FileNotFoundError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    mcp = create_server(settings)
    mode = "stateless" if settings.stateless_http else "stateful"
    print(
        f"idat-mcp listening on http://{settings.host}:{settings.port}/mcp "
        f"(mode={mode}, IDA: {settings.ida_dir}, idat: {settings.idat_path})",
        flush=True,
    )
    print("Health check: GET /health", flush=True)
    if settings.debug:
        print("Debug logging: enabled (tool start/done timings on stderr)", flush=True)
    if not settings.stateless_http:
        print(
            "Note: after server restart, reconnect MCP clients (stale mcp-session-id returns 404).",
            flush=True,
        )
    interrupted = False
    try:
        mcp.run(transport="streamable-http")
    except KeyboardInterrupt:
        interrupted = True
        print("\nidat-mcp shutting down...", flush=True)
    finally:
        shutdown_pool()
        if interrupted:
            print("idat-mcp stopped.", flush=True)
            sys.exit(0)


if __name__ == "__main__":
    main()
