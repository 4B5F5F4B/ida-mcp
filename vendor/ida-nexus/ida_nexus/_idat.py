"""Launch the console IDA host without depending on idalib or importing IDA."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path
from typing import TypedDict

from ._registry import LOG_DIR, ensure_private_directory
from ._resolver import WorkerLaunchOptions, _build_worker_command
from .cli.worker import _parser
from .errors import DatabaseOpenError


class _ProcessFlags(TypedDict, total=False):
    creationflags: int
    start_new_session: bool


def console_executable(value: str, expected_idb: str) -> Path:
    """A directory selects the 64-bit address host, or the .idb host explicitly."""
    path = Path(value).expanduser().resolve()
    if path.is_dir():
        names = (
            ("idat",) if expected_idb.lower().endswith(".idb") else ("idat64", "idat")
        )
        candidates = [
            path / (name + (".exe" if os.name == "nt" else "")) for name in names
        ]
        path = next((item for item in candidates if item.is_file()), candidates[0])
    if not path.is_file() or path.stem.lower() not in ("idat", "idat64"):
        raise DatabaseOpenError(
            f"IDA_NEXUS_IDAT must name an IDA Pro console executable or its directory: {path}"
        )
    return path


def build_console_command(
    executable: Path, bootstrap: Path, args, log: Path
) -> list[str]:
    # Pass argv directly to Popen. Only -S has its own inner argument parser.
    command = [
        str(executable),
        "-A",
        "-a",
        f'-S"{bootstrap}"',
        f"-L{args.log_file or log}",
    ]
    for name, switch in (
        ("compiler", "C"),
        ("processor", "p"),
        ("plugin_options", "O"),
        ("output_database", "o"),
        ("windows_dir", "W"),
    ):
        value = getattr(args, name)
        if value:
            command.append(f"-{switch}{value}")
    for name, switch in (
        ("new_database", "c"),
        ("disable_fpp", "f"),
        ("disable_mouse", "M"),
        ("load_resources", "R"),
        ("empty_database", "t"),
        ("no_segmentation", "x"),
    ):
        if getattr(args, name):
            command.append(f"-{switch}")
    if args.output_database and "-c" not in command:
        command.append("-c")
    if args.image_base is not None:
        command.append(f"-b{args.image_base // 16:X}")
    if args.entry_point is not None:
        command.append(f"-i{args.entry_point:X}")
    if args.jit_debugger is not None:
        command.append(f"-I{int(args.jit_debugger)}")
    if args.db_compression:
        command.append(
            {"compress": "-P+", "pack": "-P", "no_pack": "-P-"}[args.db_compression]
        )
    command.extend(f"-d{value}" for value in args.first_pass_directive)
    command.extend(f"-D{value}" for value in args.second_pass_directive)
    if args.file_type:
        command.append(
            f"-T{args.file_type}" + (f":{args.file_member}" if args.file_member else "")
        )
    if args.debug_mask:
        command.append(f"-z{args.debug_mask:X}")
    if args.debug_flag:
        raise DatabaseOpenError(
            "idat workers require numeric debug_flags instead of flag names"
        )
    if args.run_debugger:
        raise DatabaseOpenError("idat analysis workers do not support run_debugger")
    if args.script_file:
        raise DatabaseOpenError(
            "idat reserves -S for its service; run scripts with execute_python after opening"
        )
    command.append(str(args.input))
    return command


def spawn_idat(
    source: str, expected_idb: str, lease_grace: float, options: WorkerLaunchOptions
):
    environment = dict(os.environ if options.worker_env is None else options.worker_env)
    # IDAPython uses its configured DLL, not the MCP virtual environment.
    for name in ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"):
        environment.pop(name, None)
    executable = console_executable(environment["IDA_NEXUS_IDAT"], expected_idb)
    suffix = os.urandom(3).hex()
    worker_args = _build_worker_command(
        source,
        expected_idb,
        lease_grace,
        options,
        launcher=[],
        record_suffix=suffix,
    )
    args = _parser().parse_args(worker_args)
    # Use source roots, not the external Python executable/stdlib: IDAPython may
    # be Python 3.10 while the MCP process is Python 3.14.
    roots = []
    for name in ("ida_nexus", "ida_domain", "packaging", "typing_extensions"):
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None:
            raise DatabaseOpenError(f"Missing dependency for idat bootstrap: {name}")
        origin = Path(spec.origin).resolve()
        root = (
            origin.parent.parent
            if spec.submodule_search_locations is not None
            else origin.parent
        )
        if str(root) not in roots:
            roots.append(str(root))
    environment["IDA_NEXUS_IDAT_BOOTSTRAP"] = json.dumps(
        {"roots": roots, "args": vars(args)},
        default=str,
    )
    bootstrap = Path(__file__).with_name("_idat_bootstrap.py")
    log_dir = ensure_private_directory(LOG_DIR)
    # Kernel diagnostics exist even if IDAPython fails before executing -S.
    startup_log = log_dir / f"startup-{suffix}.log"
    command = build_console_command(executable, bootstrap, args, startup_log)
    kwargs: _ProcessFlags = {}
    if os.name == "nt":
        kwargs["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        )
    else:
        kwargs["start_new_session"] = True
    with startup_log.open("ab") as output:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=output,
            env=environment,
            cwd=options.worker_cwd,
            **kwargs,
        )
    return process, startup_log
