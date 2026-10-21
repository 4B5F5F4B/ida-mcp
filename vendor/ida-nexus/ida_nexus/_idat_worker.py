"""Persistent main-thread request pump for IDA 8's console host."""

from __future__ import annotations

import os
import queue
import threading
import traceback
from concurrent.futures import Future
from pathlib import Path

from ._registry import REGISTRY_DIR, InstanceIdentity
from ._runtime import (
    AnalysisState,
    IDARuntime,
    IdbChangeState,
    create_autoanalysis_hook,
    reconcile_autoanalysis_state,
)
from ._server import NexusHTTPServer
from .cli.worker import _redirect_output


class MainThreadDispatcher:
    """Marshal requests onto the -S script thread without ida_kernwin.serve()."""

    def __init__(self):
        self.owner = threading.get_ident()
        self.pending = queue.Queue()
        self.stopped = threading.Event()

    def __call__(self, callback, flags=0):
        if threading.get_ident() == self.owner:
            return callback()
        future = Future()
        self.pending.put((callback, future))
        while not future.done():
            if self.stopped.wait(0.01):
                raise RuntimeError("IDA console worker is stopping")
        return future.result()

    def stop(self):
        self.stopped.set()

    def serve(self):
        if threading.get_ident() != self.owner:
            raise RuntimeError("IDA console dispatcher must run on the IDA main thread")
        while not self.stopped.is_set():
            try:
                callback, future = self.pending.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                future.set_result(callback())
            except BaseException as exc:  # noqa: BLE001 -- marshal failures to caller
                future.set_exception(exc)


def run(configuration):
    import ida_loader
    import ida_nalt
    import ida_pro
    from ida_domain import Database

    suffix = configuration["record_suffix"]
    _redirect_output(f"{os.getpid()}-{suffix}")
    dispatcher = MainThreadDispatcher()
    analysis_state = AnalysisState()
    database = Database.open()
    runtime = IDARuntime(
        backend="idat",
        database=database,
        analysis_state=analysis_state,
        idb_change_state=IdbChangeState(),
        dispatcher=dispatcher,
    )
    hook = create_autoanalysis_hook(analysis_state)
    hook.hook()
    reconcile_autoanalysis_state(analysis_state)
    idb_path = str(Path(ida_loader.get_path(ida_loader.PATH_TYPE_IDB)).resolve())
    identity = InstanceIdentity(
        idb_path=idb_path,
        exe_path=ida_nalt.get_input_file_path() or configuration["input"],
        backend="idat",
        managed=True,
    )
    server = NexusHTTPServer(
        runtime,
        identity,
        analysis_state,
        REGISTRY_DIR,
        record_suffix=suffix,
        lease_grace=configuration["lease_grace"],
        on_shutdown=dispatcher.stop,
    )
    exit_code = 0
    try:
        if configuration["save_after_open"] and not ida_loader.save_database(
            idb_path, 0
        ):
            raise RuntimeError("Failed to save recovered database")
        server.start()
        if configuration["auto_analysis"]:
            server.start_autoanalysis()
        print(f"[ida-nexus] idat worker {server.url}", flush=True)
        dispatcher.serve()
    except BaseException:  # noqa: BLE001 -- report failures before native qexit
        traceback.print_exc()
        exit_code = 1
    finally:
        dispatcher.stop()
        server.stop()
        runtime.disable_idb_change_hook()
        hook.unhook()
        database.unhook()
        if server.save_on_shutdown and not ida_loader.save_database(idb_path, 0):
            print("[ida-nexus] failed to save database on shutdown", flush=True)
            exit_code = 1
        if not server.save_on_shutdown:
            ida_loader.set_database_flag(ida_loader.DBFL_KILL)
        # qexit closes the console database. Keep the ownership lock held until
        # kernel teardown/process exit; discovery removes the dead registration.
        ida_pro.qexit(exit_code)
