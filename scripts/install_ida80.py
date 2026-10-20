"""Install the patched GUI plugin from this checkout (Python 3.10+).

Run while IDA is closed. Existing files are backed up outside the plugin
search path. The external MCP server is installed separately with `uv sync`.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def default_plugins_dir():
    idausr = os.environ.get("IDAUSR", "").split(os.pathsep)[0].strip()
    if idausr:
        return Path(idausr).expanduser() / "plugins"
    if os.name == "nt":
        return Path(os.environ["APPDATA"]) / "Hex-Rays" / "IDA Pro" / "plugins"
    return Path.home() / ".idapro" / "plugins"


def install(plugins: Path):
    plugins = plugins.resolve()
    plugins.mkdir(parents=True, exist_ok=True)
    uv = shutil.which("uv")
    if not uv:
        raise RuntimeError(
            "Install uv and put it on PATH before running this installer"
        )
    with tempfile.TemporaryDirectory(prefix="ida-mcp-install-") as temp:
        deps = Path(temp) / "ida_mcp_deps"
        subprocess.run(
            [
                uv,
                "pip",
                "install",
                "--python-version",
                "3.10",
                "--target",
                str(deps),
                str(ROOT / "vendor/ida-domain"),
                str(ROOT / "vendor/ida-nexus"),
            ],
            check=True,
        )
        manifest = {
            "ida-nexus": "0.13.4+ida80.1",
            "ida-domain": "0.5.1+ida80.1",
            "minimum_ida": "8.0",
            "minimum_python": "3.10",
        }
        (deps / "ida-mcp-install.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")  # noqa: UP017 - Python 3.10 installer
        backup = plugins.parent / "ida-mcp-backups" / stamp
        moved = []
        created = []
        try:
            for name in ("ida_mcp_plugin.py", "ida_mcp_deps"):
                target = plugins / name
                if target.exists():
                    backup.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(target), str(backup / name))
                    moved.append(name)
            created.append("ida_mcp_deps")
            shutil.copytree(deps, plugins / "ida_mcp_deps")
            created.append("ida_mcp_plugin.py")
            shutil.copy2(ROOT / "ida_mcp_plugin.py", plugins / "ida_mcp_plugin.py")
        except BaseException:
            # Restore the previous install, including on an interrupted copy.
            for name in reversed(created):
                target = plugins / name
                target.resolve().relative_to(plugins)
                if target.is_dir():
                    shutil.rmtree(target)
                elif target.exists():
                    target.unlink()
            for name in moved:
                shutil.move(str(backup / name), str(plugins / name))
            raise
    print(f"Installed GUI plugin: {plugins / 'ida_mcp_plugin.py'}")
    if backup.exists():
        print(f"Previous installation: {backup}")
    print("Start IDA Pro 8.0 with IDAPython 3.10+, then open a disposable test binary.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugins-dir", type=Path, default=default_plugins_dir())
    args = parser.parse_args()
    install(args.plugins_dir)


if __name__ == "__main__":
    main()
