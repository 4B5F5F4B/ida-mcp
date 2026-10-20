"""Strict small SDK doubles exercise the actual legacy fallback branches.

These are not an IDA 8 runtime or a substitute for the remote smoke test.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = ROOT / "vendor/ida-domain/ida_domain"


def load_helper(name):
    spec = importlib.util.spec_from_file_location(name, DOMAIN / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "probe, expected", [(None, False), (False, False), (True, True)]
)
def test_library_detection_without_idalib(monkeypatch, probe, expected):
    sdk: Any = types.ModuleType("ida_kernwin")
    if probe is not None:
        sdk.is_ida_library = lambda *args: probe
    monkeypatch.setitem(sys.modules, "ida_kernwin", sdk)
    assert load_helper("_compat_runtime").is_ida_library() is expected


def test_byte_search_uses_legacy_compiled_pattern_overload(monkeypatch):
    sdk: Any = types.ModuleType("ida_bytes")
    sdk.BIN_SEARCH_FORWARD = 1
    sdk.BIN_SEARCH_NOSHOW = 2
    calls = []
    patterns = object()
    sdk.compiled_binpat_vec_t = lambda: patterns
    sdk.parse_binpat_str = lambda *args: calls.append(args) or ""
    sdk.bin_search = lambda *args: calls.append(args) or 0x1010
    monkeypatch.setitem(sys.modules, "ida_bytes", sdk)
    assert (
        load_helper("_compat_bytes").find_bytes(b"\x00\xff", 0x1000, 0x2000) == 0x1010
    )
    assert calls == [(patterns, 0x1000, "00 ff", 16), (0x1000, 0x2000, patterns, 3)]


def test_byte_search_preserves_modern_path(monkeypatch):
    sdk: Any = types.ModuleType("ida_bytes")
    calls = []
    sdk.find_bytes = lambda *args: calls.append(args) or 42
    monkeypatch.setitem(sys.modules, "ida_bytes", sdk)
    assert load_helper("_compat_bytes").find_bytes(b"a", 1, 99) == 42
    assert calls == [(b"a", 1, None, 99)]


@pytest.mark.parametrize(
    "data, pattern, expected",
    [(b"aaaa", b"aa", [100, 101, 102]), (b"aba", b"a", [100, 102]), (b"abc", b"z", [])],
)
def test_public_byte_searches_on_legacy_sdk(monkeypatch, data, pattern, expected):
    sdk: Any = types.ModuleType("ida_bytes")
    sdk.BIN_SEARCH_FORWARD = 1
    sdk.BIN_SEARCH_NOSHOW = 2
    sdk.compiled_binpat_vec_t = list

    def parse(patterns, start, expression, radix):
        patterns.append(bytes.fromhex(expression))
        return ""

    def search(start, end, patterns, flags):
        assert start < end
        found = data.find(patterns[0], start - 100, end - 100)
        return 100 + found if found >= 0 else -1

    sdk.parse_binpat_str = parse
    sdk.bin_search = search
    monkeypatch.setitem(sys.modules, "ida_bytes", sdk)
    # Execute the real public method bodies and compatibility helper. The rest
    # of bytes.py imports unrelated SDK functionality unavailable in pytest.
    path = DOMAIN / "bytes.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Bytes"
    )
    methods: list[ast.stmt] = [
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef)
        and n.name in {"find_bytes_between", "find_binary_sequence"}
    ]
    namespace: dict[str, Any] = {
        "find_bytes": load_helper("_compat_bytes").find_bytes,
        "ida_bytes": sdk,
        "BADADDR": -1,
        "InvalidParameterError": ValueError,
        "InvalidEAError": ValueError,
    }
    exec(  # noqa: S102 - trusted repository source
        compile(ast.Module(body=methods, type_ignores=[]), str(path), "exec"), namespace
    )
    owner = types.SimpleNamespace(
        database=types.SimpleNamespace(minimum_ea=100, maximum_ea=100 + len(data))
    )
    assert namespace["find_binary_sequence"](owner, pattern) == expected
    assert namespace["find_bytes_between"](owner, pattern) == (
        expected[0] if expected else None
    )


@pytest.mark.parametrize("analysis_failure", [False, True])
@pytest.mark.parametrize("match_notifications", [False, True])
def test_flirt_import_and_apply_without_undo_module(
    monkeypatch, analysis_failure, match_notifications
):
    events = []
    package = types.ModuleType("_ida80_domain_test")
    package.__path__ = [str(DOMAIN)]
    monkeypatch.setitem(sys.modules, package.__name__, package)
    base: Any = types.ModuleType(package.__name__ + ".base")
    base.DatabaseEntity = object
    base.check_db_open = lambda f: f
    base.decorate_all_methods = lambda decorator: lambda cls: cls
    monkeypatch.setitem(sys.modules, base.__name__, base)
    for name in (
        "ida_auto",
        "ida_diskio",
        "ida_funcs",
        "ida_idp",
        "ida_loader",
        "ida_idaapi",
    ):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "ida_undo", None)

    class Hooks:
        def hook(self):
            events.append("hook")

        def unhook(self):
            events.append("unhook")

    if match_notifications:
        monkeypatch.setattr(
            Hooks, "idasgn_matched_ea", lambda *args: None, raising=False
        )

    def auto_wait():
        events.append("wait")
        if analysis_failure:
            raise RuntimeError("analysis failed")

    vars(sys.modules["ida_idp"])["IDB_Hooks"] = Hooks
    vars(sys.modules["ida_idaapi"])["ea_t"] = int
    vars(sys.modules["ida_funcs"])["plan_to_apply_idasgn"] = lambda path: events.append(
        "apply"
    )
    vars(sys.modules["ida_auto"])["auto_wait"] = auto_wait
    spec = importlib.util.spec_from_file_location(
        package.__name__ + ".signature_files", DOMAIN / "signature_files.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    collector = module._MatchCollector("test.sig")
    collector.idasgn_matched_ea(0x1000, "function", "library")
    if match_notifications:
        assert collector.results.matches == 1
        assert collector.results.functions[0].name == "function"
    else:
        assert collector.results.matches is None
        assert collector.results.functions is None
    owner = object.__new__(module.SignatureFiles)
    with pytest.raises(NotImplementedError, match="ida_undo"):
        owner._apply(Path("test.sig"), probe_only=True)
    assert events == []
    if analysis_failure:
        with pytest.raises(RuntimeError, match="analysis failed"):
            owner._apply(Path("test.sig"))
    else:
        result = owner._apply(Path("test.sig"))
        assert result.path == "test.sig"
        assert result.matches == (0 if match_notifications else None)
    assert events == ["hook", "apply", "wait", "unhook"]


def legacy_type_sdk(monkeypatch):
    sdk: Any = types.ModuleType("ida_typeinf")
    sdk.udt_member_t = type("udt_member_t", (), {})
    sdk.enum_member_t = type("enum_member_t", (), {})
    monkeypatch.setitem(sys.modules, "ida_typeinf", sdk)
    return sdk


def test_function_arguments_without_iter_func():
    path = DOMAIN / "types.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Types"
    )
    method = next(
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "get_func_arguments"
    )
    namespace: dict[str, Any] = {
        "func_type_data_t": list,
        "FuncArgumentInfo": types.SimpleNamespace,
    }
    exec(  # noqa: S102 - trusted repository source
        compile(ast.Module(body=[method], type_ignores=[]), str(path), "exec"),
        namespace,
    )
    first_type, second_type = object(), object()

    def get_details(details):
        details.extend(
            [
                types.SimpleNamespace(name="input", type=first_type),
                types.SimpleNamespace(name="", type=second_type),
            ]
        )
        return True

    sdk_type = types.SimpleNamespace(is_func=lambda: True, get_func_details=get_details)
    result = list(namespace["get_func_arguments"](None, sdk_type))
    assert [(arg.index, arg.name, arg.type) for arg in result] == [
        (0, "input", first_type),
        (1, "arg1", second_type),
    ]
    non_function = types.SimpleNamespace(is_func=lambda: False)
    assert list(namespace["get_func_arguments"](None, non_function)) == []
    failed_details = types.SimpleNamespace(
        is_func=lambda: True, get_func_details=lambda details: False
    )
    assert list(namespace["get_func_arguments"](None, failed_details)) == []


@pytest.mark.parametrize("legacy", [True, False])
def test_structure_operand_sdk_adapters(monkeypatch, legacy):
    events = []

    class TidArray(list):
        def __init__(self, size):
            super().__init__([0] * size)

        def cast(self):
            return self

    class SignedPointer:
        def __init__(self):
            self.result = 0

        def cast(self):
            return self

        def value(self):
            return self.result

    def op_stroff(*args):
        if legacy:
            insn, operand, path, length, delta = args
            assert isinstance(path, TidArray)
            assert length == len(path)
        else:
            insn, operand, path, delta = args
            assert type(path) is list
        events.append((insn, operand, list(path), delta))
        return True

    def get_stroff_path(*args):
        if legacy:
            path, delta, ea, operand = args
            assert len(path) == 8
            assert operand == 1
            if ea == 0:
                return 0
            path[0], path[1] = 10, 20
            delta.result = -4
            return 2
        ea, operand = args
        assert operand == 1
        return ([10, 20], -4) if ea else (None, None)

    def append_fields(disp, operand, path, flags, delta, appzero):
        assert type(path) is (TidArray if legacy else list)
        assert (disp, operand, list(path), flags, delta, appzero) == (
            12,
            1,
            [10, 20],
            0,
            -4,
            True,
        )
        return ".member"

    modules = {
        "ida_kernwin": {"get_kernel_version": lambda: "8.0" if legacy else "9.5"},
        "ida_bytes": {"op_stroff": op_stroff, "get_stroff_path": get_stroff_path},
        "ida_name": {"append_struct_fields": append_fields},
        "ida_nalt": {"MAXSTRUCPATH": 8},
        "ida_pro": {"tid_array": TidArray, "sval_pointer": SignedPointer},
        "ida_struct": {
            "get_struc": lambda tid: object() if tid == 10 else None,
            "get_member_by_id": lambda tid: object() if tid == 20 else None,
            "get_struc_name": lambda tid: "Struct" if tid == 10 else None,
            "get_member_fullname": lambda tid: "Struct.member" if tid == 20 else None,
        },
        "ida_typeinf": {}
        if legacy
        else {
            "get_tid_ordinal": lambda tid: 1 if tid in (10, 20) else 0,
            "get_tid_name": lambda tid: {10: "Struct", 20: "Struct.member"}.get(tid),
        },
    }
    for name, members in modules.items():
        sdk = types.ModuleType(name)
        vars(sdk).update(members)
        monkeypatch.setitem(sys.modules, name, sdk)
    compat = load_helper("_compat_operands")
    insn = object()
    assert compat.set_struct_offset(insn, 1, [10, 20], -4)
    assert not compat.set_struct_offset(insn, 1, [], 0)
    assert not compat.set_struct_offset(insn, 1, [99], 0)
    assert not compat.set_struct_offset(insn, 1, [10, 99], 0)
    assert events == [(insn, 1, [10, 20], -4)]
    assert compat.get_struct_offset_path(100, 1) == ([10, 20], -4)
    assert compat.get_struct_offset_path(0, 1) == (None, None)
    assert compat.get_struct_path_name(10) == "Struct"
    assert compat.get_struct_path_name(20) == "Struct.member"
    assert compat.get_struct_path_name(99) is None
    assert compat.append_struct_fields(12, 1, [10, 20], -4) == ".member"


def test_type_record_renames_do_not_monkeypatch_idapython(monkeypatch):
    sdk = legacy_type_sdk(monkeypatch)
    compat = load_helper("_compat_types")
    assert compat.udm_t is sdk.udt_member_t
    assert compat.edm_t is sdk.enum_member_t
    assert not hasattr(sdk, "udm_t")


def test_numbered_types_skip_holes_and_create_independent_objects(monkeypatch):
    sdk = legacy_type_sdk(monkeypatch)
    sdk.get_ordinal_qty = lambda library: 4

    class Tinfo:
        def get_numbered_type(self, library, ordinal):
            self.ordinal = ordinal
            return ordinal != 2

    sdk.tinfo_t = Tinfo
    result = list(load_helper("_compat_types").iter_numbered_types(object()))
    assert [x.ordinal for x in result] == [1, 3]
    assert result[0] is not result[1]


def test_disabled_ordinals_do_not_enumerate_uint32_max_or_allocate(monkeypatch):
    sdk = legacy_type_sdk(monkeypatch)
    sdk.get_ordinal_qty = lambda library: 0xFFFFFFFF
    compat = load_helper("_compat_types")
    assert list(compat.iter_numbered_types(object())) == []
    with pytest.raises(NotImplementedError, match="external TIL"):
        compat.enable_numbered_types(object())


def test_local_type_ordinals_need_no_enable_api(monkeypatch):
    sdk = legacy_type_sdk(monkeypatch)
    sdk.get_ordinal_qty = lambda library: 2
    load_helper("_compat_types").enable_numbered_types(object())


def test_vendored_runtime_parses_on_python_310():
    for package in (DOMAIN, ROOT / "vendor/ida-nexus/ida_nexus"):
        for file in package.rglob("*.py"):
            ast.parse(
                file.read_text(encoding="utf-8"),
                filename=str(file),
                feature_version=(3, 10),
            )


@pytest.mark.parametrize(
    "is_qt, interactive, library, expected",
    [
        (True, None, None, True),  # IDA 8 GUI, no modern env/probe
        (False, None, None, False),  # IDA 8 text console
        (True, "0", None, False),
        (True, "1", True, False),  # idalib can report is_idaq()
        (True, "1", False, True),
    ],
)
def test_gui_detection(monkeypatch, is_qt, interactive, library, expected):
    # Compile the real detector on its own: plugin imports require IDAPython.
    path = ROOT / "vendor/ida-nexus/ida_nexus/plugin.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "is_interactive_gui"
    )
    sdk = types.SimpleNamespace(is_idaq=lambda: is_qt)
    if library is not None:
        sdk.is_ida_library = lambda *args: library
    environment = {} if interactive is None else {"IDA_IS_INTERACTIVE": interactive}
    namespace: dict[str, Any] = {
        "os": types.SimpleNamespace(environ=environment),
        "ida_kernwin": sdk,
    }
    exec(  # noqa: S102 - trusted repository source
        compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"),
        namespace,
    )
    assert namespace["is_interactive_gui"]() is expected


@pytest.mark.parametrize(
    "version, backend, supported",
    [
        ("8.0", "gui", True),
        ("8.0", "idalib", False),
        ("7.7", "gui", False),
        ("9.4", "idalib", True),
    ],
)
def test_runtime_version_checks_are_backend_specific(
    monkeypatch, version, backend, supported
):
    from ida_nexus._runtime import AnalysisState, IDARuntime, IdbChangeState

    monkeypatch.setitem(sys.modules, "ida_domain", types.ModuleType("ida_domain"))
    monkeypatch.setitem(
        sys.modules, "idaapi", types.SimpleNamespace(get_kernel_version=lambda: version)
    )
    args: dict[str, Any] = {
        "backend": backend,
        "database": object(),
        "analysis_state": AnalysisState(),
        "idb_change_state": IdbChangeState(),
    }
    if supported:
        assert IDARuntime(**args).backend == backend
    else:
        with pytest.raises(RuntimeError, match="idalib workers require"):
            IDARuntime(**args)


def load_installer(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "install_ida80", ROOT / "scripts/install_ida80.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.shutil, "which", lambda _: "uv")

    def install_packages(command, **kwargs):
        target = Path(command[command.index("--target") + 1])
        target.mkdir()
        (target / "installed-package.txt").write_text("new")

    monkeypatch.setattr(module.subprocess, "run", install_packages)
    return module


@pytest.mark.parametrize("failure", ["copy", "backup"])
def test_installer_restores_old_plugin_on_failure(tmp_path, monkeypatch, failure):
    installer = load_installer(monkeypatch)
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "ida_mcp_plugin.py").write_text("old plugin")
    deps = plugins / "ida_mcp_deps"
    deps.mkdir()
    (deps / "old.txt").write_text("old dependencies")

    def fail_copy(*args, **kwargs):
        raise OSError("simulated interrupted copy")

    real_move = installer.shutil.move

    def fail_backup(src, dst):
        if Path(src) == deps:
            raise OSError("simulated backup failure")
        return real_move(src, dst)

    if failure == "copy":
        monkeypatch.setattr(installer.shutil, "copy2", fail_copy)
    else:
        monkeypatch.setattr(installer.shutil, "move", fail_backup)
    with pytest.raises(OSError, match="simulated"):
        installer.install(plugins)
    assert (plugins / "ida_mcp_plugin.py").read_text() == "old plugin"
    assert (deps / "old.txt").read_text() == "old dependencies"
    assert not (deps / "installed-package.txt").exists()


def test_legacy_type_predicates(monkeypatch):
    sdk = legacy_type_sdk(monkeypatch)
    sdk.BTE_BITMASK = 0x10
    compat = load_helper("_compat_types")
    data = types.SimpleNamespace(bte=0x10, is_sdec=lambda: True)
    assert compat.type_predicate(data, "is_bf")
    assert compat.type_predicate(data, "is_number_signed")
    assert compat.type_predicate(data, "is_dec")
    assert not compat.type_predicate(data, "has_lzero")
    with pytest.raises(AttributeError, match="misspelled"):
        compat.type_predicate(data, "misspelled")


@pytest.mark.parametrize("temporary", [None, False, True])
def test_gui_save_without_modern_temporary_database_flag(
    monkeypatch, tmp_path, temporary
):
    from ida_nexus._runtime import APIError, IDARuntime

    loader = types.SimpleNamespace(
        PATH_TYPE_IDB=0, get_path=lambda _: str(tmp_path / "test.i64")
    )
    if temporary is not None:
        loader.DBFL_TEMP = 123
        loader.is_database_flag = lambda _: temporary
    actions = []
    monkeypatch.setitem(sys.modules, "ida_loader", loader)
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        types.SimpleNamespace(
            process_ui_action=lambda name: actions.append(name) or True
        ),
    )
    # Exercise the real save method independently of main-thread scheduling.
    runtime: Any = object.__new__(IDARuntime)
    runtime.backend = "gui"
    runtime._run_sync = lambda operation, **kwargs: operation()
    if temporary is True:
        with pytest.raises(APIError, match="Save As"):
            runtime.save_database()
        assert actions == []
    else:
        assert runtime.save_database()["saved"] is True
        assert actions == ["SaveBase"]
