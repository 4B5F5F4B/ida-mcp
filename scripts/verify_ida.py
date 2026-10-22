"""Verify the local fork against a disposable IDA database.

Usage:
  uv run python scripts/verify_ida.py --database sample.exe --expect-version 8.0 --gui-only
For GUI mode, first open the sample in IDA and load the patched plugin.
For console mode, use --idat INSTALL_DIR --headless-only; no GUI is required.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import traceback
from pathlib import Path

PROBE = r"""
import sys
from importlib.metadata import version
import idaapi, ida_bytes, ida_funcs, ida_name, ida_typeinf
from ida_domain.types import TypeKind
from ida_domain.xrefs import XrefsFlags
assert __import__("ida_domain").__version__ == "0.5.1+ida80.4", "Wrong ida-domain fork loaded"
assert version("ida-nexus") == "0.13.4+ida80.4", "Wrong ida-nexus fork loaded"

functions = list(db.functions)
assert functions, "The test binary must contain analyzed functions"
func = functions[0]
ea = func.start_ea
name = db.functions.get_name(func)
assert name, "Function name lookup failed"
disassembly = db.functions.get_disassembly(func)
assert disassembly, "Disassembly is empty"
original = ida_bytes.get_bytes(ea, min(4, func.end_ea - ea))
assert original and db.bytes.find_bytes_between(original, ea, func.end_ea) == ea
byte_matches = db.bytes.find_binary_sequence(original, ea, func.end_ea)
assert byte_matches and byte_matches[0] == ea
assert all(ida_bytes.get_bytes(match, len(original)) == original for match in byte_matches)
instruction = db.instructions.get_at(ea)
assert instruction is not None, "Instruction decoding failed"
operands = db.instructions.get_operands(instruction)
for operand in operands:
    operand.struct_offset_path()
    operand.struct_offset_path_names()
segments = list(db.segments)
assert segments, "No segments"
strings = list(db.strings)
xrefs = list(db.xrefs.to_ea(ea))
xref_filter_checks = 0
for iterate in (db.xrefs.to_ea, db.xrefs.from_ea):
    all_refs = list(iterate(ea))
    for flags, expected in (
        (XrefsFlags.CODE, [ref for ref in all_refs if ref.is_code]),
        (XrefsFlags.DATA, [ref for ref in all_refs if not ref.is_code]),
        (XrefsFlags.NOFLOW, [ref for ref in all_refs if not ref.is_flow]),
        (XrefsFlags.CODE_NOFLOW, [ref for ref in all_refs if ref.is_code and not ref.is_flow]),
    ):
        assert list(iterate(ea, flags)) == expected, f"Xref filter failed: {flags}"
        xref_filter_checks += 1
named_types = list(db.types.get_all())
numbered_types = list(db.types.get_all(type_kind=TypeKind.NUMBERED))
tif = db.types.parse_one_declaration(None, "int __cdecl ida80_probe(int value);")
assert tif is not None, "Type declaration parsing failed"
arguments = list(db.types.get_func_arguments(tif))
assert len(arguments) == 1 and arguments[0].name == "value"
assert db.types.get_func_argument_count(tif) == len(arguments)
assert db.types.get_func_argument_by_index(tif, 0).name == "value"
old_comment = ida_bytes.get_cmt(ea, False)
marker = "ida-mcp compatibility smoke test"
try:
    assert ida_bytes.set_cmt(ea, marker, False)
    assert ida_bytes.get_cmt(ea, False) == marker
finally:
    assert ida_bytes.set_cmt(ea, old_comment or "", False)
decompiler = {"available": bool(__import__("ida_hexrays").init_hexrays_plugin())}
if decompiler["available"]:
    text = db.pseudocode.get_text(ea)
    assert text, "Decompiler returned no text"
    decompiler["lines"] = len(text)
report = {
    "kernel": idaapi.get_kernel_version(),
    "python": sys.version,
    "domain_source": __import__("ida_domain").__file__,
    "nexus_source": __import__("ida_nexus").__file__,
    "functions": len(functions), "first_function": name,
    "segments": len(segments), "strings": len(strings),
    "xrefs_to_first_function": len(xrefs),
    "named_types": len(named_types), "numbered_types": len(numbered_types),
    "decompiler": decompiler,
    "comment_write_and_restore": True,
    "byte_search": {"first_match": ea, "all_match_count": len(byte_matches)},
    "operand_paths_read": len(operands),
    "function_type_arguments": len(arguments),
    "xref_filter_checks": xref_filter_checks,
}
report
"""


class MCPClient:
    """Minimal stdio client; exercise the public MCP wire protocol."""

    def __init__(self, *, command=None, env=None):
        self.stderr = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")  # noqa: SIM115 - owned until close()
        self.process = subprocess.Popen(
            command
            or [
                sys.executable,
                "-c",
                "from ida_mcp.cli import main; raise SystemExit(main())",
                "stdio",
                "--agent=ida-compat-verifier",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
            encoding="utf-8",
            env=env,
        )
        assert self.process.stdin is not None and self.process.stdout is not None
        self.stdin = self.process.stdin
        self.stdout = self.process.stdout
        self.messages = queue.Queue()
        self.request_id = 0

        def read():
            try:
                for line in self.stdout:
                    self.messages.put(json.loads(line))
            except (ValueError, OSError) as exc:
                self.messages.put(exc)
            finally:
                self.messages.put(EOFError("MCP server closed stdout"))

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()

    def request(self, method, params):
        self.request_id += 1
        self.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": self.request_id,
                    "method": method,
                    "params": params,
                }
            )
            + "\n"
        )
        self.stdin.flush()
        while True:
            response = self.messages.get(timeout=360)
            if isinstance(response, Exception):
                self.stderr.seek(0)
                raise RuntimeError(f"{response}\n{self.stderr.read()}")  # noqa: TRY004 - remote process failure
            if response.get("id") != self.request_id:
                continue
            if "error" in response:
                raise RuntimeError(response["error"])
            return response["result"]

    def call(self, name, arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError(result)
        if "structuredContent" in result:
            return result["structuredContent"]
        text = "\n".join(
            c["text"] for c in result.get("content", []) if c["type"] == "text"
        )
        try:
            return json.loads(text)
        except ValueError:
            return text

    def close(self):
        self.stdin.close()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=15)
        finally:
            self.stdout.close()
            self.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--expect-version", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--gui-only", action="store_true")
    mode.add_argument("--headless-only", action="store_true")
    parser.add_argument(
        "--idat", type=Path, help="Console executable or IDA installation directory"
    )
    parser.add_argument("--output", type=Path, default=Path("ida-compat-report.json"))
    args = parser.parse_args()
    if args.idat:
        os.environ["IDA_NEXUS_IDAT"] = str(args.idat.resolve(strict=True))
    path = args.database.resolve(strict=True)
    client = MCPClient()
    try:
        client.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "ida-compat-verifier", "version": "1"},
            },
        )
        client.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        client.stdin.flush()
        tools = client.request("tools/list", {})["tools"]
        assert {t["name"] for t in tools} == {
            "open_database",
            "execute_python",
            "reference",
            "list_databases",
            "save_database",
            "close_database",
        }
        if args.gui_only:
            target = os.path.normcase(str(path))
            instances = client.call("list_databases", {})["instances"]
            if not any(
                item["backend"] == "gui"
                and os.path.normcase(str(Path(item["path"]).resolve())) == target
                for item in instances
            ):
                raise RuntimeError(
                    "Open this exact binary/IDB in IDA with the patched GUI plugin first"
                )
        opened = client.call("open_database", {"path": str(path)})
        if args.gui_only and opened["backend"] != "gui":
            raise RuntimeError("Expected an IDA GUI database")
        if args.headless_only and opened["backend"] != "idat":
            raise RuntimeError("Expected an automatically launched idat database")
        instance = opened["instance_id"]
        # Exercise the exact first-call regression through MCP: this also
        # waits for initial analysis on a newly created console database.
        for _ in range(2):
            hello = client.call(
                "execute_python",
                {"code": 'print("hello")', "instance_id": instance, "timeout": 10},
            )
            assert hello["stdout"] == "hello\n", hello
            assert not hello["stderr"], hello
        if args.headless_only:
            try:
                client.call(
                    "execute_python",
                    {
                        "code": "while True: pass",
                        "instance_id": instance,
                        "timeout": 0.2,
                    },
                )
            except RuntimeError as exc:
                assert "execute timed out" in str(exc), str(exc)
            else:
                raise AssertionError("Python loop was not interrupted")
            recovered = client.call(
                "execute_python",
                {"code": "40 + 2", "instance_id": instance, "timeout": 10},
            )
            assert recovered["result"] == 42, recovered
        kernel = client.call(
            "execute_python",
            {
                "code": "import idaapi; idaapi.get_kernel_version()",
                "instance_id": instance,
            },
        )["result"]
        if kernel != args.expect_version:
            raise RuntimeError(
                f"Wrong IDA kernel: expected {args.expect_version}, got {kernel}"
            )
        reference = client.call("reference", {"query": "functions"})
        assert reference, "API reference is empty"
        result = client.call("execute_python", {"code": PROBE, "instance_id": instance})
        if result["stderr"]:
            raise RuntimeError(result["stderr"])
        report = result["result"]
        if report["kernel"] != args.expect_version:
            raise RuntimeError(
                f"Wrong IDA kernel: expected {args.expect_version}, got {report['kernel']}"
            )
        saved = client.call("save_database", {"instance_id": instance})
        report["save"] = saved
        report["close"] = client.call("close_database", {"instance_id": instance})
        report["backend"] = opened["backend"]
        report["transport"] = "MCP stdio"
        report["hello_calls"] = 2
        report["timeout_recovery_checked"] = args.headless_only
        report["success"] = True
        args.output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(json.dumps(report, indent=2, ensure_ascii=False))
    except Exception as exc:
        args.output.write_text(
            json.dumps(
                {
                    "success": False,
                    "expected_kernel": args.expect_version,
                    "database": str(path),
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        raise
    finally:
        client.close()


if __name__ == "__main__":
    main()
