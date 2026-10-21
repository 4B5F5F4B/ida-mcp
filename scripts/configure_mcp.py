"""Check the local MCP installation and merge a Claude-style mcpServers entry."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import tempfile
import tomllib
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from verify_ida import MCPClient

ROOT = Path(__file__).resolve().parents[1]


def check_packages(root: Path = ROOT) -> None:
    for distribution, module in (
        ("ida-nexus", "ida_nexus"),
        ("ida-domain", "ida_domain"),
    ):
        directory = root / "vendor" / distribution
        expected = tomllib.loads(
            (directory / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]["version"]
        actual = version(distribution)
        if actual != expected:
            raise RuntimeError(f"{distribution}: expected {expected}, found {actual}")
        spec = importlib.util.find_spec(module)
        if (
            spec is None
            or spec.origin is None
            or Path(spec.origin).resolve()
            != (directory / module / "__init__.py").resolve()
        ):
            raise RuntimeError(
                f"{distribution} is not loaded from this compatibility checkout"
            )
        print(f"Verified {distribution} {actual}: {spec.origin}")


def check_mcp(entry: dict[str, Any]) -> None:
    # Exercise the exact command written to JSON, without opening any database.
    client = MCPClient(
        command=[entry["command"], *entry["args"]], env={**os.environ, **entry["env"]}
    )
    try:
        client.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "ida-mcp-installer", "version": "1"},
            },
        )
        client.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        client.stdin.flush()
        names = {item["name"] for item in client.request("tools/list", {})["tools"]}
        required = {
            "open_database",
            "execute_python",
            "reference",
            "list_databases",
            "save_database",
            "close_database",
        }
        if not required <= names:
            raise RuntimeError(f"Missing MCP tools: {sorted(required - names)}")
        print("Verified MCP stdio startup and all six tools")
    finally:
        client.close()


def merge_config(path: Path, name: str, entry: dict[str, Any]) -> Path | None:
    """Preserve unrelated settings; back up and atomically replace valid JSON."""
    original = path.read_bytes() if path.exists() else None
    document = json.loads(original.decode("utf-8-sig")) if original is not None else {}
    if not isinstance(document, dict):
        raise TypeError("MCP configuration must be a JSON object")
    servers = document.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise TypeError("mcpServers must be a JSON object")
    if servers.get(name) == entry:
        return None
    servers[name] = entry
    content = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if original is not None:
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
        backup = path.with_name(path.name + f".bak-{stamp}")
        shutil.copy2(path, backup)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return backup


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--uv", type=Path, required=True)
    parser.add_argument("--ida-dir", type=Path, required=True)
    parser.add_argument("--server-name", default="ida80")
    args = parser.parse_args()
    if not args.server_name.strip():
        parser.error("--server-name must not be empty")
    entry = {
        "command": str(args.uv.resolve(strict=True)),
        "args": [
            "--directory",
            str(ROOT),
            "run",
            "--locked",
            "ida-mcp",
            "stdio",
            "--agent=code-agent",
        ],
        "env": {"IDA_NEXUS_IDAT": str(args.ida_dir.resolve(strict=True))},
    }
    # Preserve customized discovery paths so Agent and IDA use the same registry.
    for key in ("IDAUSR", "IDA_NEXUS_STATE_DIR", "IDA_MCP_STATE_DIR"):
        if os.environ.get(key):
            entry["env"][key] = os.environ[key]
    check_packages()
    check_mcp(entry)
    backup = merge_config(args.config.resolve(), args.server_name, entry)
    if backup:
        print(f"Previous configuration: {backup}")
    print(f"MCP configuration: {args.config.resolve()}")


if __name__ == "__main__":
    main()
