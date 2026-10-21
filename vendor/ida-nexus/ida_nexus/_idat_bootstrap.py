"""IDA -S entry point. Keep imports minimal until the external roots are added."""

import json
import os
import sys
import traceback


def bootstrap():
    configuration = json.loads(os.environ.pop("IDA_NEXUS_IDAT_BOOTSTRAP"))
    sys.path[:0] = configuration["roots"]
    # A previously installed GUI plugin may import an older dependency bundle
    # during console initialization. Do not mix it with the worker's package.
    for name in tuple(sys.modules):
        if name in ("ida_nexus", "ida_domain") or name.startswith(
            ("ida_nexus.", "ida_domain.")
        ):
            del sys.modules[name]
    from ida_nexus._idat_worker import run

    run(configuration["args"])


try:
    bootstrap()
except BaseException:  # noqa: BLE001 -- startup must exit rather than leave idat waiting
    traceback.print_exc()
    import ida_pro

    ida_pro.qexit(1)
