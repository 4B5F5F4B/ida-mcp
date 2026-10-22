"""Runtime detection shared by IDA 8 GUI and modern idalib hosts."""

from __future__ import annotations

import sys
from pathlib import Path


def is_ida_library() -> bool:
    import ida_kernwin

    # IDAPython initializes this marker in embedded GUI/console hosts. With
    # IDAPYTHON_VENV_EXECUTABLE, sys.executable can name python.exe instead of
    # idat.exe, so executable-name detection alone would load a second kernel.
    if getattr(sys.modules.get('__main__'), 'IDAPYTHON_VERSION', None) is not None:
        return False

    # Modern console hosts may themselves use the library UI shim. They still
    # own an already-open database; importing idapro would load a second kernel.
    if Path(sys.executable).stem.lower() in ('idat', 'idat64'):
        return False

    # idalib did not exist in IDA 8. A missing probe inside IDAPython means
    # a GUI/text IDA process, not a request to load a second kernel.
    probe = getattr(ida_kernwin, 'is_ida_library', None)
    return bool(probe(None, 0, None)) if probe is not None else False
