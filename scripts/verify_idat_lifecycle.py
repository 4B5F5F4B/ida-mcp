"""Exercise console worker lifecycle on disposable copies, without opening a GUI."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--idat", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expect-version", required=True)
    parser.add_argument(
        "--output", type=Path, default=Path("idat-lifecycle-report.json")
    )
    args = parser.parse_args()
    # Keep failing copies and worker logs for diagnostics as well as evidence.
    work = Path(tempfile.mkdtemp(prefix="ida-console-test-"))
    os.environ["IDA_NEXUS_IDAT"] = str(args.idat.resolve(strict=True))
    os.environ["IDA_NEXUS_STATE_DIR"] = str(work / "nexus")
    from ida_nexus import (
        DatabaseHandle,
        DatabaseOpenOptions,
        RemoteError,
        wait_database_released,
    )
    from ida_nexus.database_state import probe_database_state

    source = work / "first sample.exe"
    other = work / "second sample.exe"
    shutil.copyfile(args.binary, source)
    shutil.copyfile(args.binary, other)
    report: dict[str, Any] = {
        "work_directory": str(work),
        "success": False,
        "checks": [],
    }
    handles = []

    def opened(path=source, **options):
        handle = DatabaseHandle.open(str(path), options=DatabaseOpenOptions(**options))
        handles.append(handle)
        assert handle.instance.backend == "idat"
        kernel = handle.execute_python("import idaapi; idaapi.get_kernel_version()")[
            "result"
        ]
        assert kernel == args.expect_version, kernel
        return handle

    def released(handle):
        assert wait_database_released(handle.instance, timeout=30), (
            "worker did not release its database"
        )
        handle.close()

    def check(name):
        report["checks"].append(name)
        print(name, flush=True)

    try:
        first = opened(auto_analysis=False)
        first.wait_autoanalysis(timeout=60)
        assert first.execute_python("len(list(db.functions))")["result"] > 0
        check("fresh load and explicit analysis")
        shared = opened()
        assert shared.instance.record_id == first.instance.record_id
        first.close(wait_for_database=True)
        assert shared.execute_python("6 * 7")["result"] == 42
        check("shared worker survives first client close")
        parallel = opened(other)
        assert parallel.instance.pid != shared.instance.pid
        parallel.close(wait_for_database=True)
        released(parallel)
        check("separate input gets independent worker")

        comment = "import ida_bytes; ea = next(iter(db.functions)).start_ea; "
        shared.execute_python(
            comment + "ida_bytes.set_cmt(ea, 'saved-console-marker', False)"
        )
        shared.save_database()
        try:
            shared.execute_python("while True: pass", timeout=0.2)
        except RemoteError as exc:
            assert "timeout" in str(exc).lower() or "timed out" in str(exc).lower(), (
                str(exc)
            )
        else:
            raise AssertionError("infinite operation was not interrupted")
        assert shared.execute_python("40 + 2")["result"] == 42
        check("timed out execution leaves worker usable")
        shared.close(wait_for_database=True)
        released(shared)
        assert probe_database_state(source)["state"] == "packed"
        check("final close saves and releases packed database")

        reopened = opened()
        assert (
            reopened.execute_python(comment + "ida_bytes.get_cmt(ea, False)")["result"]
            == "saved-console-marker"
        )
        reopened.execute_python(
            comment + "ida_bytes.set_cmt(ea, 'discard-console-marker', False)"
        )
        reopened.shutdown_database(save=False)
        released(reopened)
        restored = opened()
        assert (
            restored.execute_python(comment + "ida_bytes.get_cmt(ea, False)")["result"]
            == "saved-console-marker"
        )
        restored.close(wait_for_database=True)
        released(restored)
        check("reopen preserves saved data and shutdown discards unsaved edit")

        idle = opened(idle_timeout=1.0)
        deadline = time.monotonic() + 15
        while idle.connected and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not idle.connected
        released(idle)
        check("idle lease expires and shuts down worker")
        report["success"] = True
        report["kernel"] = args.expect_version
    except BaseException as exc:
        report["error"] = repr(exc)
        raise
    finally:
        for handle in handles:
            handle.close()
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
