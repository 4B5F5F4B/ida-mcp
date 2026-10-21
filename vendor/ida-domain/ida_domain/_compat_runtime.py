"""Runtime detection shared by IDA 8 GUI and modern idalib hosts."""

from __future__ import annotations

import sys
from pathlib import Path


def is_ida_library() -> bool:
    import ida_kernwin

    # Modern console hosts may themselves use the library UI shim. They still
    # own an already-open database; importing idapro would load a second kernel.
    if Path(sys.executable).stem.lower() in ('idat', 'idat64'):
        return False

    # idalib did not exist in IDA 8. A missing probe inside IDAPython means
    # a GUI/text IDA process, not a request to load a second kernel.
    probe = getattr(ida_kernwin, 'is_ida_library', None)
    return bool(probe(None, 0, None)) if probe is not None else False
