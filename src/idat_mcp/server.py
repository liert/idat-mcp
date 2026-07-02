from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from idat_mcp.config import Settings
from idat_mcp.tools import register_tools


def _transport_security(settings: Settings) -> TransportSecuritySettings | None:
    if settings.host in ("127.0.0.1", "localhost", "::1"):
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        )

    if settings.allowed_hosts:
        origins = []
        for host in settings.allowed_hosts:
            if host.startswith("http://") or host.startswith("https://"):
                origins.append(host if host.endswith(":*") else f"{host}:*")
            else:
                origins.append(f"http://{host}" if ":*" in host else f"http://{host}:*")
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=settings.allowed_hosts,
            allowed_origins=origins,
        )

    # Remote bind without explicit allowlist: disable DNS rebinding checks.
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


def create_server(settings: Settings) -> FastMCP:
    mcp = FastMCP(
        "idat-mcp",
        host=settings.host,
        port=settings.port,
        json_response=True,
        stateless_http=settings.stateless_http,
        transport_security=_transport_security(settings),
    )
    register_tools(mcp, ida_dir=str(settings.ida_dir), max_workers=settings.max_workers)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_request):
        from starlette.responses import JSONResponse

        return JSONResponse({"status": "ok", "service": "idat-mcp", "mcp_path": "/mcp"})

    return mcp
