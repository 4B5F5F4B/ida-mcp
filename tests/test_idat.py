from __future__ import annotations

import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from ida_nexus import _idat, _resolver
from ida_nexus._idat_worker import MainThreadDispatcher
from ida_nexus._registry import (
    InstanceIdentity,
    InstanceRegistration,
    load_registry_entry,
)
from ida_nexus._resolver import WorkerLaunchOptions, _build_worker_command
from ida_nexus.cli.worker import _parser
from ida_nexus.errors import DatabaseOpenError


def test_console_directory_selection(tmp_path):
    ext = ".exe" if os.name == "nt" else ""
    host = tmp_path / f"idat64{ext}"
    host.touch()
    small = tmp_path / f"idat{ext}"
    small.touch()
    assert _idat.console_executable(str(tmp_path), "sample.exe.i64") == host
    assert _idat.console_executable(str(tmp_path), "sample.idb") == small
    with pytest.raises(DatabaseOpenError):
        _idat.console_executable(str(tmp_path / "ida.exe"), "sample.exe.i64")


def test_console_arguments_and_existing_database(tmp_path):
    source = tmp_path / "raw file.bin"
    database = tmp_path / "output file.i64"
    options = WorkerLaunchOptions(
        image_base=0x400000, processor="metapc", load_resources=True
    )

    def command():
        args = _parser().parse_args(
            _build_worker_command(
                str(source),
                str(database),
                20,
                options,
                launcher=[],
                record_suffix="123abc",
            )
        )
        return _idat.build_console_command(
            Path("idat64.exe"), tmp_path / "a b.py", args, tmp_path / "log.txt"
        )

    argv = command()
    assert argv[-1] == str(source)
    assert "-b40000" in argv and "-pmetapc" in argv and "-R" in argv
    assert f"-o{database}" in argv and "-c" in argv
    assert f'-S"{tmp_path / "a b.py"}"' in argv
    assert "-A" in argv and "-a" in argv and "-B" not in argv
    database.touch()
    argv = command()
    assert argv[-1] == str(database)
    assert not any(arg.startswith(("-b", "-p", "-o")) for arg in argv)
    assert "-R" not in argv and "-c" not in argv


@pytest.mark.parametrize(
    "options",
    [
        WorkerLaunchOptions(script_file="user.py"),
        WorkerLaunchOptions(run_debugger="win32"),
        WorkerLaunchOptions(debug_flags=("queue",)),
    ],
)
def test_unsupported_console_options_fail_before_start(options):
    args = _parser().parse_args(
        _build_worker_command(
            "input.exe",
            "input.exe.i64",
            20,
            options,
            launcher=[],
            record_suffix="123abc",
        )
    )
    with pytest.raises(DatabaseOpenError):
        _idat.build_console_command(
            Path("idat64.exe"), Path("bootstrap.py"), args, Path("log")
        )


def test_console_spawn_is_hidden_and_isolates_python_environment(tmp_path, monkeypatch):
    executable = tmp_path / "idat64.exe"
    executable.touch()
    calls = []

    def popen(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(_idat.subprocess, "Popen", popen)
    options = WorkerLaunchOptions(
        worker_env={
            "IDA_NEXUS_IDAT": str(executable),
            "VIRTUAL_ENV": "python314env",
            "PYTHONHOME": "python314",
            "PYTHONPATH": "wrong-path",
            "KEEP_ME": "value",
        }
    )
    _, log = _resolver.spawn_worker("input.exe", "input.exe.i64", 20, options)
    command, kwargs = calls[0]
    assert command[0] == str(executable)
    env = kwargs["env"]
    assert not {"VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"} & env.keys()
    assert env["KEEP_ME"] == "value"
    assert "PATH" not in env  # caller's complete environment stays complete
    config = json.loads(env["IDA_NEXUS_IDAT_BOOTSTRAP"])
    assert config["args"]["managed"]
    assert log.name == f"startup-{config['args']['record_suffix']}.log"
    assert all(Path(root).is_dir() for root in config["roots"])
    if os.name == "nt":
        assert kwargs["creationflags"] & _idat.subprocess.CREATE_NO_WINDOW


def test_dispatcher_marshals_to_owner_and_propagates_failure():
    ready = threading.Event()
    holder = []

    def main_thread():
        dispatcher = MainThreadDispatcher()
        holder.append(dispatcher)
        ready.set()
        dispatcher.serve()

    thread = threading.Thread(target=main_thread)
    thread.start()
    assert ready.wait(2)
    dispatcher = holder[0]
    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(dispatcher, threading.get_ident) for _ in range(8)
            ]
            assert {future.result(timeout=2) for future in futures} == {thread.ident}
        with pytest.raises(ZeroDivisionError):
            dispatcher(lambda: 1 / 0)
        # A hook cleanup on the owner thread must execute directly, not deadlock.
        assert dispatcher(lambda: dispatcher(lambda: 42)) == 42
    finally:
        dispatcher.stop()
        thread.join(timeout=2)
    assert not thread.is_alive()
    with pytest.raises(RuntimeError, match="stopping"):
        dispatcher(lambda: 42)


def test_idat_registry_round_trip(tmp_path):
    identity = InstanceIdentity(
        idb_path=str(tmp_path / "sample.i64"), exe_path="", backend="idat", managed=True
    )
    registration = InstanceRegistration(
        tmp_path / "instances", identity, token="test-token"
    )
    try:
        entry = registration.publish(12345)
        assert registration.registry_path is not None
        assert load_registry_entry(registration.registry_path).backend == "idat"
        assert entry.managed
    finally:
        registration.release()


def test_console_startup_timeout_terminates_owned_process(tmp_path, monkeypatch):
    source = tmp_path / "sample.exe"
    source.touch()
    stopped = []
    process: Any = SimpleNamespace(
        args=["idat64.exe"],
        poll=lambda: None,
        terminate=lambda: stopped.append("terminate"),
        wait=lambda timeout: stopped.append("wait"),
    )
    monkeypatch.setattr(_resolver, "_scan_until", lambda *a, **kw: [])

    def fail(*args):
        raise TimeoutError("startup timed out")

    monkeypatch.setattr(_resolver, "_await_ready", fail)
    with pytest.raises(TimeoutError, match="startup timed out"):
        _resolver.resolve_instance(
            source, spawner=lambda *args: (process, tmp_path / "log")
        )
    assert stopped == ["terminate", "wait"]


def test_console_successful_early_exit_is_fatal(tmp_path, monkeypatch):
    process: Any = SimpleNamespace(args=["idat64.exe"], pid=123, poll=lambda: 0)
    monkeypatch.setattr(_resolver, "_scan_until", lambda *a, **kw: [])
    import time

    from ida_nexus.errors import WorkerStartError

    with pytest.raises(WorkerStartError, match="exited with status 0"):
        _resolver._await_ready(
            process,
            str(tmp_path / "a.i64"),
            tmp_path / "startup-123abc.log",
            time.monotonic() + 10,
        )
