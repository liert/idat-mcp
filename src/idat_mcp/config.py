from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    ida_dir: Path
    idat_path: Path
    host: str
    port: int
    idle_timeout: int
    max_workers: int | None
    stateless_http: bool
    allowed_hosts: list[str]

    @classmethod
    def from_cli(
        cls,
        *,
        ida_dir: str,
        host: str = "127.0.0.1",
        port: int = 8745,
        idle_timeout: int = 1800,
        max_workers: int | None = None,
        stateless_http: bool = False,
        allowed_hosts: list[str] | None = None,
    ) -> Settings:
        ida_path = Path(ida_dir).expanduser().resolve()
        return cls(
            ida_dir=ida_path,
            idat_path=ida_path / "idat",
            host=host,
            port=port,
            idle_timeout=idle_timeout,
            max_workers=max_workers,
            stateless_http=stateless_http,
            allowed_hosts=list(allowed_hosts or []),
        )

    def validate(self) -> None:
        if not self.ida_dir.is_dir():
            raise FileNotFoundError(
                f"IDA installation directory not found: {self.ida_dir}. "
                "Pass a valid path with --ida-dir."
            )
        if not self.idat_path.is_file():
            raise FileNotFoundError(
                f"idat binary not found: {self.idat_path}. "
                "Ensure --ida-dir points to a valid IDA Pro installation."
            )
        libidalib = self.ida_dir / "libidalib.so"
        if not libidalib.is_file():
            raise FileNotFoundError(
                f"libidalib.so not found in {self.ida_dir}. "
                "Ensure IDA Pro 9+ with idalib is installed."
            )

    def apply(self) -> None:
        os.environ["IDADIR"] = str(self.ida_dir)
