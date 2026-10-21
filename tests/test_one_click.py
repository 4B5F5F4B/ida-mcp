from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


@pytest.fixture
def config_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("configure_mcp")


def test_merge_preserves_other_servers_and_backs_up_original(tmp_path, config_module):
    path = tmp_path / "agent config.json"
    original = b'{"mcpServers":{"other":{"command":"old"},"ida80":{"command":"upstream"}},"settings":{"enabled":true}}'
    path.write_bytes(original)
    entry = {
        "command": "C:\\tools with spaces\\uv.exe",
        "env": {"IDA_NEXUS_IDAT": "C:\\IDA"},
    }
    backup = config_module.merge_config(path, "ida80", entry)
    assert backup.read_bytes() == original
    result = json.loads(path.read_text(encoding="utf-8"))
    assert result["settings"] == {"enabled": True}
    assert result["mcpServers"]["other"] == {"command": "old"}
    assert result["mcpServers"]["ida80"] == entry
    assert config_module.merge_config(path, "ida80", entry) is None
    assert len(list(tmp_path.glob("*.bak-*"))) == 1


@pytest.mark.parametrize(
    "content", [b"{invalid", b"[]", b'{"mcpServers": []}', b"null"]
)
def test_invalid_configuration_is_not_overwritten(tmp_path, config_module, content):
    path = tmp_path / "config.json"
    path.write_bytes(content)
    with pytest.raises((TypeError, ValueError)):
        config_module.merge_config(path, "ida80", {"command": "uv"})
    assert path.read_bytes() == content
    assert list(tmp_path.iterdir()) == [path]


def test_merge_accepts_powershell_bom_and_unicode(tmp_path, config_module):
    path = tmp_path / "config.json"
    path.write_text('{"label":"分析"}', encoding="utf-8-sig")
    config_module.merge_config(path, "ida80", {"command": "D:\\工具\\uv.exe"})
    result = json.loads(path.read_text(encoding="utf-8"))
    assert result["label"] == "分析"
    assert result["mcpServers"]["ida80"]["command"] == "D:\\工具\\uv.exe"


def test_failed_replace_preserves_configuration(tmp_path, config_module, monkeypatch):
    path = tmp_path / "config.json"
    original = b'{"mcpServers": {"other": {}}}'
    path.write_bytes(original)

    def denied(*args):
        raise PermissionError("locked config")

    monkeypatch.setattr(config_module.os, "replace", denied)
    with pytest.raises(PermissionError, match="locked config"):
        config_module.merge_config(path, "ida80", {"command": "uv"})
    assert path.read_bytes() == original
    assert (
        len(list(tmp_path.iterdir())) == 2
    )  # original plus its backup, no partial JSON


def test_package_check_rejects_upstream_version(config_module, monkeypatch):
    monkeypatch.setattr(config_module, "version", lambda name: "0.13.4")
    with pytest.raises(RuntimeError, match="expected.*found"):
        config_module.check_packages()
